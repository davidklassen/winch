package module

import (
	"archive/tar"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// Touch is a path that a checked step changes. Tree is set when the step
// removes or replaces what is at the path, so a restore needs its content.
type Touch struct {
	Path string
	Tree bool
}

// Touches returns the paths that a checked step changes. Check sets what it
// needs: the entries that purge removes, and the home of the keys of a user.
func Touches(m Module) []Touch {
	switch m := m.(type) {
	case *File:
		return []Touch{{m.Path, true}}
	case *Link:
		return []Touch{{m.Path, true}}
	case *Line:
		return []Touch{{m.Path, true}}
	case *Unit:
		return []Touch{{m.Path(), true}}
	case *Repo, *Certbot:
		var out []Touch
		for _, p := range m.(Writer).Writes() {
			out = append(out, Touch{p, true})
		}
		return out
	case *Download:
		out := []Touch{{m.Path, true}}
		if m.Unpack != "" {
			out = append(out, Touch{m.Unpack, false})
		}
		return out
	case *Dir:
		if m.Absent {
			return []Touch{{m.Path, true}}
		}
		// A recursive owner change reaches the whole tree.
		out := []Touch{{m.Path, m.Recurse}}
		for _, r := range m.removed {
			out = append(out, Touch{r, true})
		}
		return out
	case *User:
		var out []Touch
		if m.mkHome != "" {
			out = append(out, Touch{m.mkHome, false})
		}
		if m.keys {
			out = append(out, Touch{path.Join(m.keyHome, ".ssh"), false}, Touch{path.Join(m.keyHome, ".ssh", "authorized_keys"), true})
		}
		return out
	case *Hostname:
		return []Touch{{hostnameFile, true}}
	case *Timezone:
		return []Touch{{localtime, true}, {timezoneFile, true}}
	case *Firewall:
		var out []Touch
		for _, p := range firewallPaths {
			out = append(out, Touch{p, true})
		}
		return out
	}
	return nil
}

// Login is the login user of a session, as Guard needs it.
type Login struct{ entry passwdEntry }

// LookupLogin returns the login user with the ID uid, or nil when the
// accounts do not know it.
func LookupLogin(uid uint32) (*Login, error) {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if errors.As(err, new(user.UnknownUserIdError)) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &Login{passwdEntry{name: u.Username, uid: uid, home: u.HomeDir}}, nil
}

func (l *Login) Name() string { return l.entry.name }

// Guard returns the plan line of a step whose change can lock out the login
// user: it changes the user's authorized_keys, a directory on its path in
// the home, or the sudo rules of a login user other than root. It returns ""
// for another step, and for an unknown login user.
func Guard(touches []Touch, login *Login) string {
	if login == nil {
		return ""
	}
	return guard(touches, login.entry)
}

func guard(touches []Touch, u passwdEntry) string {
	keys := path.Join(u.home, ".ssh", "authorized_keys")
	for _, t := range touches {
		inHome := t.Path == u.home || t.Path == path.Dir(keys)
		if t.Path == keys || strings.HasPrefix(keys, t.Path+"/") && (t.Tree || inHome) {
			return "changes the keys of the login user " + u.name
		}
	}
	if u.uid == 0 {
		return ""
	}
	for _, t := range touches {
		if t.Path == "/etc/sudoers" || t.Path == sudoersDir || strings.HasPrefix(t.Path, sudoersDir+"/") {
			return "changes the sudo rules, which the login user " + u.name + " needs"
		}
	}
	return ""
}

const sudoersDir = "/etc/sudoers.d"

// Saved is the state of a path before a step changed it. A restore removes a
// Missing path, puts back the owner, group, and mode of a Dir, or replaces
// the path with the tree in the tar file Archive.
type Saved struct {
	Path    string `json:"path"`
	Missing bool   `json:"missing,omitempty"`
	Dir     *Attrs `json:"dir,omitempty"`
	Archive string `json:"archive,omitempty"`
}

type Attrs struct {
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid"`
	Mode uint32 `json:"mode"`
}

// Save keeps the state of the path of t. A path below a missing directory
// saves the top missing directory, so a restore removes what the step
// created. An existing directory without Tree saves its attributes; another
// path saves a tar file at archive with the path and its tree.
func Save(t Touch, archive string) (Saved, error) {
	s, err := save(t, archive)
	if err != nil {
		return Saved{}, fmt.Errorf("keep the old state of %s for the rollback: %w", t.Path, err)
	}
	return s, nil
}

func save(t Touch, archive string) (Saved, error) {
	dir, missing, err := openParent(t.Path)
	if err != nil {
		return Saved{}, err
	}
	defer dir.Close()
	if len(missing) > 0 {
		return Saved{Path: missing[0], Missing: true}, nil
	}
	name := path.Base(t.Path)
	fi, err := dir.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return Saved{Path: t.Path, Missing: true}, nil
	}
	if err != nil {
		return Saved{}, err
	}
	if fi.IsDir() && !t.Tree {
		st := fi.Sys().(*syscall.Stat_t)
		return Saved{Path: t.Path, Dir: &Attrs{st.Uid, st.Gid, uint32(st.Mode) & 0o7777}}, nil
	}
	f, err := os.OpenFile(archive, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return Saved{}, err
	}
	tw := tar.NewWriter(f)
	err = addTree(tw, dir, name, name, fi)
	if err == nil {
		err = tw.Close()
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(archive)
		return Saved{}, err
	}
	return Saved{Path: t.Path, Archive: archive}, nil
}

// addTree writes the entry name of dir, with fi, to tw as rel, and the
// entries below a directory. It never follows a symbolic link.
func addTree(tw *tar.Writer, dir *os.Root, name, rel string, fi fs.FileInfo) error {
	st := fi.Sys().(*syscall.Stat_t)
	h := &tar.Header{Name: rel, Mode: int64(st.Mode & 0o7777), Uid: int(st.Uid), Gid: int(st.Gid), ModTime: fi.ModTime(), Format: tar.FormatPAX}
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		target, err := dir.Readlink(name)
		if err != nil {
			return err
		}
		h.Typeflag, h.Linkname = tar.TypeSymlink, target
		return tw.WriteHeader(h)
	case fi.Mode().IsRegular():
		f, err := openSame(dir, name, fi)
		if err != nil {
			return err
		}
		defer f.Close()
		h.Typeflag, h.Size = tar.TypeReg, fi.Size()
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		_, err = io.Copy(tw, f)
		return err
	case fi.IsDir():
		h.Typeflag = tar.TypeDir
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		sub, err := openRoot(dir, name, fi)
		if err != nil {
			return err
		}
		defer sub.Close()
		d, err := sub.Open(".")
		if err != nil {
			return err
		}
		names, err := d.Readdirnames(-1)
		d.Close()
		if err != nil {
			return err
		}
		slices.Sort(names)
		for _, n := range names {
			info, err := sub.Lstat(n)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			if err := addTree(tw, sub, n, rel+"/"+n, info); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("%s is %s; the rollback keeps only files, directories, and symbolic links", path.Join(dir.Name(), name), kind(fi))
}

// Restore puts back the saved paths in reverse order, runs systemctl
// daemon-reload when it put back a path in /etc/systemd, restarts an active
// ssh.socket when it put back sshd's config, and loads the firewall again
// when it put back its file. It restores every
// path it can and returns the errors.
func Restore(ctx context.Context, saved []Saved) error {
	var errs []error
	for _, s := range slices.Backward(saved) {
		if err := restore(s); err != nil {
			errs = append(errs, fmt.Errorf("put back %s: %w", s.Path, err))
		}
	}
	var socket bool
	if slices.ContainsFunc(saved, func(s Saved) bool { return sshdConfig(s.Path) }) {
		var err error
		if socket, err = sshSocketUp(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if reloads(saved) || socket {
		if _, err := run(ctx, nil, "systemctl", "daemon-reload"); err != nil {
			errs = append(errs, err)
		}
	}
	if socket {
		if err := restartSSHSocket(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if loadsFirewall(saved) {
		if err := loadFirewall(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func restore(s Saved) error {
	dir, missing, err := openParent(s.Path)
	if err != nil {
		return err
	}
	defer dir.Close()
	name := path.Base(s.Path)
	if s.Missing {
		if len(missing) > 0 {
			return nil
		}
		return dir.RemoveAll(name)
	}
	if len(missing) > 0 {
		sub, err := mkdirs(dir, missing)
		if err != nil {
			return err
		}
		defer sub.Close()
		dir = sub
	}
	if s.Dir != nil {
		return restoreDir(dir, name, *s.Dir)
	}
	return extract(dir, name, s.Archive)
}

// restoreDir puts back the owner, group, and mode of the directory name.
func restoreDir(dir *os.Root, name string, a Attrs) error {
	fi, err := dir.Lstat(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return err
	case fi.IsDir():
		sub, err := openRoot(dir, name, fi)
		if err != nil {
			return err
		}
		defer sub.Close()
		return setRootAttrs(sub, a.UID, a.GID, a.Mode)
	default:
		if err := dir.RemoveAll(name); err != nil {
			return err
		}
	}
	sub, err := mkdir(dir, name, a.UID, a.GID, a.Mode)
	if err != nil {
		return err
	}
	return sub.Close()
}

// extract unpacks the tree in the tar file archive under a temporary name in
// dir, and then moves it to name.
func extract(dir *os.Root, name, archive string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	tmp := ".winch-" + rand.Text()
	defer dir.RemoveAll(tmp) //nolint:errcheck // after the rename, nothing is left to remove
	tr := tar.NewReader(f)
	var dirs []*tar.Header
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		rel, ok := strings.CutPrefix(h.Name, name)
		if !ok || rel != "" && !strings.HasPrefix(rel, "/") || strings.Contains(rel, "/../") || strings.HasSuffix(rel, "/..") {
			return fmt.Errorf("%s holds %s, which is not below %s", archive, h.Name, name)
		}
		h.Name = tmp + rel
		if err := extractEntry(dir, h, tr); err != nil {
			return err
		}
		if h.Typeflag == tar.TypeDir {
			dirs = append(dirs, h)
		}
	}
	for _, h := range slices.Backward(dirs) {
		if err := dir.Chown(h.Name, h.Uid, h.Gid); err != nil {
			return err
		}
		if err := dir.Chmod(h.Name, fileMode(uint32(h.Mode))); err != nil {
			return err
		}
		if err := dir.Chtimes(h.Name, h.ModTime, h.ModTime); err != nil {
			return err
		}
	}
	fi, err := dir.Lstat(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return err
	case fi.IsDir() || len(dirs) > 0:
		if err := dir.RemoveAll(name); err != nil {
			return err
		}
	}
	return dir.Rename(tmp, name)
}

func extractEntry(dir *os.Root, h *tar.Header, r io.Reader) error {
	switch h.Typeflag {
	case tar.TypeDir:
		return dir.Mkdir(h.Name, 0o700)
	case tar.TypeSymlink:
		if err := dir.Symlink(h.Linkname, h.Name); err != nil {
			return err
		}
		return dir.Lchown(h.Name, h.Uid, h.Gid)
	case tar.TypeReg:
		err := writeFile(dir, h.Name, r, uint32(h.Uid), uint32(h.Gid), uint32(h.Mode), func(tmp string) error {
			return dir.Rename(tmp, h.Name)
		})
		if err != nil {
			return err
		}
		return dir.Chtimes(h.Name, h.ModTime, h.ModTime)
	}
	return fmt.Errorf("%s has the unknown entry type %q", h.Name, h.Typeflag)
}

// reloads reports whether systemd must read its unit files again after a
// restore of saved.
func reloads(saved []Saved) bool {
	return slices.ContainsFunc(saved, func(s Saved) bool { return strings.HasPrefix(s.Path, "/etc/systemd/") })
}

// SSHSocket reports whether a step that changes touches needs a restart of
// ssh.socket: it changes sshd's config, and ssh.socket is active. The
// sshd-socket-generator writes the Port and ListenAddress of sshd's config
// into ssh.socket at daemon-reload. A socket that failed, for example on a
// port that another program holds, counts as active.
func SSHSocket(ctx context.Context, touches []Touch) (bool, error) {
	if !slices.ContainsFunc(touches, func(t Touch) bool { return sshdConfig(t.Path) }) {
		return false, nil
	}
	return sshSocketUp(ctx)
}

func sshSocketUp(ctx context.Context) (bool, error) {
	u, err := showUnit(ctx, "ssh.socket")
	if err != nil {
		return false, err
	}
	return u.up() || u.active == "failed", nil
}

// RestartSSHSocket makes ssh.socket listen as sshd's config says.
func RestartSSHSocket(ctx context.Context) error {
	if _, err := run(ctx, nil, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	return restartSSHSocket(ctx)
}

func restartSSHSocket(ctx context.Context) error {
	// A restart of ssh.socket starts ssh.service twice. A few restarts in a
	// row, such as a change and its rollback, reach the start limit of
	// ssh.service, 5 starts in 10 seconds. Then ssh.socket fails and closes
	// every port. reset-failed resets the counter.
	if _, err := run(ctx, nil, "systemctl", "reset-failed", "ssh.service", "ssh.socket"); err != nil {
		return err
	}
	_, err := run(ctx, nil, "systemctl", "restart", "ssh.socket")
	return err
}

func sshdConfig(p string) bool {
	return p == "/etc/ssh/sshd_config" || p == "/etc/ssh/sshd_config.d" || strings.HasPrefix(p, "/etc/ssh/sshd_config.d/")
}
