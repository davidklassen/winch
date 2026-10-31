package module

import (
	"archive/tar"
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
)

const (
	dpkgInfo    = "/var/lib/dpkg/info"
	ucfRegistry = "/var/lib/ucf/registry"
	archives    = "/var/cache/apt/archives"
)

// hostContent is the content of a file step that comes from the host: a
// file for copy_from, or the package archive for stock.
type hostContent struct {
	// line is the plan line of a content change.
	line string
	// from names the source in the plan line of the attributes of a missing
	// source.
	from string
	// missing is the error of apply when the source does not exist yet, or
	// nil.
	missing error
	sum     string
	// owner and group are those of the archive entry of stock. They are
	// empty for copy_from. The mode of copy_from has no setuid, setgid,
	// sticky, or group and others write bit: a user's file must not give
	// that user a root config.
	owner string
	group string
	mode  uint32
	// content is the archive entry of stock, or the source file of
	// copy_from.
	content io.ReadSeeker
}

func (h *hostContent) close() {
	if c, ok := h.content.(io.Closer); ok {
		_ = c.Close()
	}
}

// reader returns the content from its start.
func (h *hostContent) reader() (io.Reader, error) {
	_, err := h.content.Seek(0, io.SeekStart)
	return h.content, err
}

var errNoSource = errors.New("the source does not exist")

// copySource reads the copy_from source p.
func copySource(p string) (*hostContent, error) {
	h := &hostContent{line: "content from " + p, from: p}
	f, fi, err := openSource(p)
	if errors.Is(err, errNoSource) {
		h.line += " (does not exist yet)"
		h.missing = fmt.Errorf("%s does not exist", p)
		return h, nil
	}
	if err != nil {
		return nil, err
	}
	h.content = f
	if h.sum, err = fileSHA(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("read %s: %w", p, err)
	}
	h.mode = uint32(fi.Mode().Perm()) &^ 0o022
	return h, nil
}

// openSource opens the file at p. It follows a symbolic link at p and in its
// parents only in a directory that only root can write, as openPath does.
func openSource(p string) (*os.File, fs.FileInfo, error) {
	cur := p
	for links := 0; ; links++ {
		if links > 40 {
			return nil, nil, fmt.Errorf("%s: %w", p, errLinkLevels)
		}
		f, fi, next, err := openSourceStep(cur)
		if next == "" || err != nil {
			return f, fi, err
		}
		cur = next
	}
}

// openSourceStep opens the file at p, or returns the absolute target of the
// symbolic link at p.
func openSourceStep(p string) (*os.File, fs.FileInfo, string, error) {
	dir, missing, err := openParent(p)
	if _, ok := errors.AsType[*noPathError](err); ok {
		// An earlier step can make the parent.
		return nil, nil, "", errNoSource
	}
	if err != nil {
		return nil, nil, "", err
	}
	defer dir.Close()
	if len(missing) > 0 {
		return nil, nil, "", errNoSource
	}
	name := path.Base(p)
	fi, err := dir.Lstat(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil, "", errNoSource
	case err != nil:
		return nil, nil, "", err
	case fi.Mode()&fs.ModeSymlink != 0:
		if err := linkAllowed(dir, name); err != nil {
			return nil, nil, "", err
		}
		target, err := dir.Readlink(name)
		if err == nil && !path.IsAbs(target) {
			target = path.Join(dir.Name(), target)
		}
		return nil, nil, target, err
	case !fi.Mode().IsRegular():
		return nil, nil, "", fmt.Errorf("%s is %s, not a file", p, kind(fi))
	}
	f, err := openSame(dir, name, fi)
	return f, fi, "", err
}

// stockSource reads what the installed package that owns p ships for p.
func stockSource(ctx context.Context, p string) (*hostContent, error) {
	h := &hostContent{line: "content of the package that ships " + p + " (no installed package ships it yet)", from: "the package"}
	owners, err := dpkgOwners(os.DirFS(dpkgInfo), map[string]bool{p: true})
	if err != nil {
		return nil, err
	}
	pkg := owners[p]
	if pkg == "" {
		registry, err := os.ReadFile(ucfRegistry)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		if pkg = ucfOwner(registry, p); pkg != "" {
			return nil, fmt.Errorf("%s makes %s with ucf and ships no copy; use copy_from with its source in /usr/share", pkg, p)
		}
		h.missing = fmt.Errorf("no installed package ships %s", p)
		return h, nil
	}
	out, err := run(ctx, nil, "dpkg-query", "-W", "-f=${Version}\t${Architecture}\t${db:Status-Abbrev}", pkg)
	if err != nil {
		return nil, err
	}
	fields := strings.Split(out, "\t")
	if len(fields) != 3 {
		return nil, fmt.Errorf("dpkg-query %s: unexpected output %q", pkg, out)
	}
	version, arch, status := fields[0], fields[1], fields[2]
	// The second letter of the status is the state; the first is the
	// selection, such as h for a held package.
	if len(status) < 2 || status[1] != 'i' {
		h.missing = fmt.Errorf("no installed package ships %s; %s is not installed", p, pkg)
		return h, nil
	}
	name, _, _ := strings.Cut(pkg, ":")
	deb := path.Join(archives, archiveName(name, version, arch))
	if _, err := os.Stat(deb); errors.Is(err, fs.ErrNotExist) {
		if err := download(ctx, pkg+"="+version, deb); err != nil {
			return nil, fmt.Errorf("get the archive of %s %s: %w", name, version, err)
		}
	} else if err != nil {
		return nil, err
	}
	data, hdr, err := debEntry(ctx, deb, p)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", name, version, err)
	}
	h.line = "content of " + name + " " + version
	h.content, h.sum = bytes.NewReader(data), sha(data)
	h.owner = cmp.Or(hdr.Uname, strconv.Itoa(hdr.Uid))
	h.group = cmp.Or(hdr.Gname, strconv.Itoa(hdr.Gid))
	h.mode = uint32(hdr.Mode) & 0o7777
	return h, nil
}

// debEntry returns the content and the header of the file p in the package
// archive deb. It reads the data archive as dpkg-deb unpacks it, and stops at
// p.
func debEntry(ctx context.Context, deb, p string) ([]byte, *tar.Header, error) {
	cmd := exec.CommandContext(ctx, "dpkg-deb", "--fsys-tarfile", deb)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.WaitDelay = KillDelay
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	data, hdr, err := tarEntry(out, p)
	if err == nil {
		// The processes of dpkg-deb, also its decompressor, end on the
		// closed pipe.
		_ = out.Close()
		_ = cmd.Wait()
		return data, hdr, nil
	}
	// dpkg-deb runs to its end, so Wait gets its own error.
	_, _ = io.Copy(io.Discard, out)
	if werr := cmd.Wait(); werr != nil {
		return nil, nil, failure("dpkg-deb", werr, stderr.String())
	}
	return nil, nil, err
}

// download puts the archive of the package version spec, such as
// nginx-common=1.26.3-3, into apt's cache as deb. apt-get download writes
// to the final name as data arrives, so a killed download in the cache
// would leave a partial archive at deb. apt-get clean warns about a
// directory in the cache, so the directory of the download is next to it.
func download(ctx context.Context, spec, deb string) error {
	dir := path.Join(path.Dir(archives), "winch")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	for _, d := range []string{archives, dir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	defer os.RemoveAll(dir)
	ctx, cancel := context.WithTimeoutCause(ctx, commandLimit, noResult(commandLimit))
	defer cancel()
	cmd := exec.CommandContext(ctx, "apt-get", "download", "-q", "-o", "APT::Sandbox::User=root", spec)
	cmd.Dir = dir
	cmd.Env = append(cmd.Environ(), aptEnv...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := wait(ctx, cmd, KillDelay); err != nil {
		return failure("apt-get download", err, out.String())
	}
	return os.Rename(path.Join(dir, path.Base(deb)), deb)
}

// archiveName is the name of a package archive in apt's cache.
func archiveName(pkg, version, arch string) string {
	return pkg + "_" + strings.ReplaceAll(version, ":", "%3a") + "_" + arch + ".deb"
}

// tarEntry returns the content and the header of the file p in the data
// archive of a package.
func tarEntry(r io.Reader, p string) ([]byte, *tar.Header, error) {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil, nil, fmt.Errorf("the archive has no %s", p)
		}
		if err != nil {
			return nil, nil, err
		}
		if strings.TrimSuffix(strings.TrimPrefix(hdr.Name, "."), "/") != p {
			continue
		}
		switch hdr.Typeflag {
		case tar.TypeReg:
			data, err := io.ReadAll(tr)
			return data, hdr, err
		case tar.TypeDir:
			return nil, nil, fmt.Errorf("the archive has %s as a directory, not a file", p)
		case tar.TypeSymlink:
			return nil, nil, fmt.Errorf("the archive has %s as a symbolic link, not a file", p)
		}
		return nil, nil, fmt.Errorf("the archive has %s as a special entry, not a file", p)
	}
}

// dpkgOwners returns the package that owns each path of want, from the file
// lists in fsys, the info directory of dpkg. A path that no package owns is
// missing from the map.
func dpkgOwners(fsys fs.FS, want map[string]bool) (map[string]string, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	owners := map[string]string{}
	for _, e := range entries {
		pkg, ok := strings.CutSuffix(e.Name(), ".list")
		if !ok {
			continue
		}
		data, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			return nil, err
		}
		for line := range bytes.Lines(data) {
			if p := string(bytes.TrimSuffix(line, []byte("\n"))); want[p] && owners[p] == "" {
				owners[p] = pkg
			}
		}
		if len(owners) == len(want) {
			break
		}
	}
	return owners, nil
}

// ucfOwner returns the package that registers p in registry, the content of
// the ucf registry, or "" when none does. A line is the package, white
// space, and the path.
func ucfOwner(registry []byte, p string) string {
	for line := range bytes.Lines(registry) {
		if f := bytes.Fields(line); len(f) == 2 && string(f[1]) == p {
			return string(f[0])
		}
	}
	return ""
}
