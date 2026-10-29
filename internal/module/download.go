package module

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/davidklassen/winch/internal/yamlx"
)

type Download struct {
	URL    string         `yaml:"url,required" json:"url"`
	SHA256 string         `yaml:"sha256,required" json:"sha256"`
	Path   string         `yaml:"path" json:"path,omitempty"`
	Unpack string         `yaml:"unpack" json:"unpack,omitempty"`
	Owner  yamlx.NameOrID `yaml:"owner" json:"owner,omitempty"`
	Group  yamlx.NameOrID `yaml:"group" json:"group,omitempty"`
	Mode   string         `yaml:"mode" json:"mode,omitempty"`

	// Recorded is the Record of the last successful unpack into Unpack, or
	// "".
	Recorded string `json:"-"`
}

func (d *Download) Main() string {
	if d.Unpack != "" {
		return d.Unpack
	}
	return d.Path
}

var sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

var archiveTypes = []string{".tar.gz", ".tgz", ".tar.xz", ".zip"}

func (d *Download) Validate() error {
	if strings.ContainsFunc(d.URL, unicode.IsControl) {
		return &yamlx.FieldError{Field: "url", Msg: "has a control character"}
	}
	if u, err := url.Parse(d.URL); err != nil || u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
		return &yamlx.FieldError{Field: "url", Msg: "must be an http or https URL"}
	}
	if !sha256Re.MatchString(d.SHA256) {
		return &yamlx.FieldError{Field: "sha256", Msg: "must be 64 lowercase hexadecimal digits, as sha256sum prints them"}
	}
	switch {
	case d.Path != "" && d.Unpack != "":
		return &yamlx.FieldError{Field: "unpack", Msg: "a download step takes path or unpack, not both"}
	case d.Path != "":
		if err := checkPath(d.Path); err != nil {
			return err
		}
	case d.Unpack == "":
		return &yamlx.FieldError{Msg: "a download step needs path or unpack"}
	default:
		if d.Unpack == "/" {
			return &yamlx.FieldError{Field: "unpack", Msg: "must not be /"}
		}
		if err := checkAbs("unpack", d.Unpack); err != nil {
			return err
		}
		if d.archiveType() == "" {
			return &yamlx.FieldError{Field: "url", Msg: "unpack needs a URL whose path ends in .tar.gz, .tgz, .tar.xz, or .zip"}
		}
		if d.Mode != "" {
			return &yamlx.FieldError{Field: "mode", Msg: "unpack takes the modes of the archive, without write permission for group and others; it takes no mode"}
		}
	}
	if err := checkOwner("owner", d.Owner); err != nil {
		return err
	}
	if err := checkOwner("group", d.Group); err != nil {
		return err
	}
	return checkMode(d.Mode, "0755")
}

// archiveType returns the archive suffix of the path of the URL, or "".
func (d *Download) archiveType() string {
	u, err := url.Parse(d.URL)
	if err != nil {
		return ""
	}
	for _, t := range archiveTypes {
		if strings.HasSuffix(u.Path, t) {
			return t
		}
	}
	return ""
}

func (d *Download) Check(ctx context.Context, st *State, _ func(string)) (Result, error) {
	owner, group, mode, err := attrs(d.Owner, d.Group, d.Mode, "0644")
	if err != nil {
		return Result{}, err
	}
	if d.Unpack != "" {
		return d.checkUnpack(owner, group)
	}
	dir, missing, err := openParent(d.Path)
	if err != nil {
		return Result{}, err
	}
	defer dir.Close()
	name := path.Base(d.Path)
	fi, exists, err := lstat(dir, name, missing)
	if err != nil {
		return Result{}, err
	}
	if !exists {
		changes := append(parentChanges(missing), "download "+d.URL, attrLine(owner, group, mode)+userNote(owner, group))
		return Result{Status: Change, Action: Create, Changes: changes}, nil
	}
	if !fi.Mode().IsRegular() {
		return Result{}, fmt.Errorf("%s is %s, not a file", d.Path, kind(fi))
	}
	same, err := d.same(dir, name, fi)
	if err != nil {
		return Result{}, err
	}
	res := Result{Status: OK}
	if !same {
		res = Result{Status: Change, Action: Modify, Changes: []string{"download " + d.URL + " (the sha256 differs)"}}
	}
	changes, err := attrChanges(fi, owner, group, mode)
	if err != nil {
		return Result{}, err
	}
	if len(changes) > 0 {
		res.Status, res.Action = Change, Modify
		res.Changes = append(res.Changes, changes...)
	}
	if res.Status == Change {
		if err := noFlags(dir, name, fi, d.Path); err != nil {
			return Result{}, err
		}
	}
	return res, nil
}

// checkUnpack compares the record of the last unpack with the step. It reads
// no archive. It reads the old tree only when the step unpacks again, since
// apply removes the tree.
func (d *Download) checkUnpack(owner, group string) (Result, error) {
	parent, missing, err := openParent(d.Unpack)
	if err != nil {
		return Result{}, err
	}
	defer parent.Close()
	fi, exists, err := lstat(parent, path.Base(d.Unpack), missing)
	if err != nil {
		return Result{}, err
	}
	unpack := "unpack into " + d.Unpack + " (owner " + owner + ", group " + group + userNote(owner, group) + ")"
	switch {
	case !exists:
		return Result{Status: Change, Action: Create, Changes: append(parentChanges(missing), "download "+d.URL, unpack)}, nil
	case !fi.IsDir():
		return Result{}, fmt.Errorf("%s is %s, not a directory", d.Unpack, kind(fi))
	}
	rec := strings.SplitN(d.Recorded, ":", 3)
	var why string
	switch {
	case d.Recorded == "":
		why = "no record of an earlier download"
	case len(rec) != 3 || rec[0] != d.SHA256:
		why = "new sha256"
	case rec[1] != owner && rec[2] != group:
		why = "new owner and group"
	case rec[1] != owner:
		why = "new owner"
	case rec[2] != group:
		why = "new group"
	default:
		return Result{Status: OK}, nil
	}
	t, err := walkTree(parent, path.Base(d.Unpack), d.Unpack, fi)
	if err != nil {
		return Result{}, err
	}
	changes := []string{"download " + d.URL + " (" + why + ")", unpack}
	if d.Recorded == "" {
		changes = append(changes, "remove its content: "+t.counts())
	}
	return Result{Status: Change, Action: Modify, Changes: changes}, nil
}

// Record is what the helper records after a successful unpack:
// <sha256>:<owner>:<group>.
func (d *Download) Record() string {
	owner, group, _, _ := attrs(d.Owner, d.Group, "", "0644")
	return d.SHA256 + ":" + owner + ":" + group
}

// same reports whether the file name in dir has the step's checksum.
func (d *Download) same(dir *os.Root, name string, fi fs.FileInfo) (bool, error) {
	r, err := openSame(dir, name, fi)
	if err != nil {
		return false, err
	}
	defer r.Close()
	sum, err := fileSHA(r)
	return sum == d.SHA256, err
}

func (d *Download) Apply(ctx context.Context, note func(string)) error {
	owner, group, mode, err := attrs(d.Owner, d.Group, d.Mode, "0644")
	if err != nil {
		return err
	}
	uid, gid, err := ids(owner, group)
	if err != nil {
		return err
	}
	if d.Unpack != "" {
		return d.applyUnpack(ctx, uid, gid, note)
	}
	dir, missing, err := openParent(d.Path)
	if err != nil {
		return err
	}
	defer dir.Close()
	name := path.Base(d.Path)
	fi, exists, err := lstat(dir, name, missing)
	if err != nil {
		return err
	}
	if exists && fi.Mode().IsRegular() {
		same, err := d.same(dir, name, fi)
		if err != nil {
			return err
		}
		if same {
			r, err := openSame(dir, name, fi)
			if err != nil {
				return err
			}
			defer r.Close()
			return setAttrs(r, uid, gid, mode)
		}
	}
	sub, err := mkdirs(dir, missing)
	if err != nil {
		return err
	}
	defer sub.Close()
	tmpName := ".winch-" + rand.Text()
	tmp, err := sub.OpenFile(tmpName, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer sub.Remove(tmpName)
	defer tmp.Close()
	if err := d.get(ctx, tmp, note); err != nil {
		return err
	}
	if err := tmp.Chown(int(uid), int(gid)); err != nil {
		return err
	}
	if err := tmp.Chmod(fileMode(mode)); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	return sub.Rename(tmpName, name)
}

// applyUnpack downloads the archive to a temporary file next to the unpack
// directory and checks every entry. It unpacks the archive into a new
// directory with the owner uid and the group gid. The new directory takes the
// owner, group, and mode of an existing unpack directory. It swaps the two
// directories and removes the old tree.
func (d *Download) applyUnpack(ctx context.Context, uid, gid uint32, note func(string)) error {
	parent, missing, err := openParent(d.Unpack)
	if err != nil {
		return err
	}
	defer parent.Close()
	sub, err := mkdirs(parent, missing)
	if err != nil {
		return err
	}
	defer sub.Close()
	tmpName := ".winch-" + rand.Text()
	tmp, err := sub.OpenFile(tmpName, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer sub.Remove(tmpName)
	defer tmp.Close()
	if err := d.get(ctx, tmp, note); err != nil {
		return err
	}
	note("unpack into " + d.Unpack)
	typ := d.archiveType()
	if err := (unpacker{}).read(ctx, tmp, typ); err != nil {
		return fmt.Errorf("unpack %s: %w", d.URL, err)
	}
	name := path.Base(d.Unpack)
	newName := ".winch-unpack-" + name
	// A killed unpack leaves the new directory, or the old tree after the
	// swap.
	if err := sub.RemoveAll(newName); err != nil {
		return fmt.Errorf("remove the tree of a stopped unpack into %s: %w", d.Unpack, err)
	}
	fi, exists, err := lstat(sub, name, nil)
	if err != nil {
		return err
	}
	if exists && !fi.IsDir() {
		return fmt.Errorf("%s is %s, not a directory", d.Unpack, kind(fi))
	}
	dirUID, dirGID, dirMode := uid, gid, uint32(0o755)
	// A dir step can set the owner and mode of the unpack directory.
	if exists {
		st := fi.Sys().(*syscall.Stat_t)
		dirUID, dirGID, dirMode = st.Uid, st.Gid, uint32(st.Mode)&0o7777
	}
	root, err := mkdir(sub, newName, dirUID, dirGID, dirMode)
	if err != nil {
		return err
	}
	defer sub.RemoveAll(newName) //nolint:errcheck // the error of the unpack or the swap explains the failure
	defer root.Close()
	if err := (unpacker{root: root, path: d.Unpack, uid: uid, gid: gid}).read(ctx, tmp, typ); err != nil {
		return fmt.Errorf("unpack %s into %s: %w", d.URL, d.Unpack, err)
	}
	if !exists {
		return sub.Rename(newName, name)
	}
	if err := exchange(sub, newName, name); err != nil {
		return fmt.Errorf("swap the new tree into %s: %w", d.Unpack, err)
	}
	if err := sub.RemoveAll(newName); err != nil {
		return fmt.Errorf("remove the old tree of %s: %w", d.Unpack, err)
	}
	return nil
}

// get writes the body of the URL to w. It fails when the checksum differs.
func (d *Download) get(ctx context.Context, w io.Writer, note func(string)) error {
	note("download " + d.URL)
	sum, err := fetch(ctx, d.URL, w, stallLimit)
	if err != nil {
		return fmt.Errorf("download %s: %w", d.URL, err)
	}
	if sum != d.SHA256 {
		return fmt.Errorf("download %s: the SHA-256 is %s, not %s", d.URL, sum, d.SHA256)
	}
	return nil
}

// stallLimit is the time without data after which a download fails.
const stallLimit = 2 * time.Minute

// fetch writes the body of url to w and returns its SHA-256. It fails when
// no data arrives for stall.
func fetch(ctx context.Context, url string, w io.Writer, stall time.Duration) (string, error) {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	timer := time.AfterFunc(stall, func() { cancel(fmt.Errorf("no data for %s", stall)) })
	defer timer.Stop()
	sum, err := fetchBody(ctx, url, io.MultiWriter(w, writerFunc(func(p []byte) (int, error) {
		timer.Reset(stall)
		return len(p), nil
	})))
	if err != nil && ctx.Err() != nil {
		return "", context.Cause(ctx)
	}
	var cerr *tls.CertificateVerificationError
	if errors.As(err, &cerr) {
		if _, serr := os.Stat(caBundle); errors.Is(serr, fs.ErrNotExist) {
			return "", errors.New("the host has no CA certificates; install the package ca-certificates with an earlier pkg step")
		}
	}
	return sum, err
}

// caBundle is the file of the package ca-certificates.
const caBundle = "/etc/ssl/certs/ca-certificates.crt"

// userAgent names winch to the server: some servers refuse the User-Agent
// of Go.
var userAgent = "winch/" + mainVersion()

func mainVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		return bi.Main.Version
	}
	return ""
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func fetchBody(ctx context.Context, url string, w io.Writer) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)
	// Go reads the system's CA certificates once per process. A step can add
	// a CA certificate after an earlier download, so each download reads
	// them again.
	pem, err := os.ReadFile(caBundle)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	t := http.DefaultTransport.(*http.Transport).Clone()
	defer t.CloseIdleConnections()
	t.TLSClientConfig = &tls.Config{RootCAs: roots}
	// The checksum is of the bytes that the server sends.
	t.DisableCompression = true
	resp, err := (&http.Client{Transport: t}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errors.New(resp.Status)
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(w, h), resp.Body); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// unpacker writes the entries of an archive into root. Without a root, it
// only checks the entries. Errors name the entries below path.
type unpacker struct {
	root     *os.Root
	path     string
	uid, gid uint32
}

// read reads the archive f of the type typ from its start.
func (u unpacker) read(ctx context.Context, f *os.File, typ string) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	switch typ {
	case ".tar.gz", ".tgz":
		zr, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		return u.tar(zr)
	case ".tar.xz":
		return u.tarXZ(ctx, f)
	default:
		fi, err := f.Stat()
		if err != nil {
			return err
		}
		zr, err := zip.NewReader(f, fi.Size())
		if err != nil {
			return err
		}
		return u.zip(zr)
	}
}

// tarXZ reads the archive through xz, from the package xz-utils.
func (u unpacker) tarXZ(ctx context.Context, f *os.File) error {
	ctx, cancel := context.WithTimeoutCause(ctx, commandLimit, fmt.Errorf("no result after %s", commandLimit))
	defer cancel()
	cmd := exec.CommandContext(ctx, "xz", "-dc")
	cmd.Dir = "/"
	cmd.Stdin = f
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); errors.Is(err, exec.ErrNotFound) {
		return errors.New("xz is missing; install the package xz-utils with an earlier pkg step")
	} else if err != nil {
		return err
	}
	if err := u.tar(out); err != nil {
		// xz ends on the closed pipe. An xz that failed first has written
		// its error, which explains the error of tar.
		out.Close()
		if werr := cmd.Wait(); stderr.Len() > 0 {
			return failure("xz", werr, stderr.String())
		}
		return err
	}
	// The end of the tar archive can come before the end of the xz stream.
	_, _ = io.Copy(io.Discard, out)
	if err := cmd.Wait(); err != nil {
		return failure("xz", err, stderr.String())
	}
	return nil
}

func (u unpacker) tar(r io.Reader) error {
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name, err := entryName(h.Name)
		if err != nil {
			return err
		}
		switch h.Typeflag {
		case tar.TypeDir, tar.TypeReg, tar.TypeSymlink, tar.TypeXGlobalHeader:
		case tar.TypeLink:
			if _, err := entryName(h.Linkname); err != nil {
				return err
			}
		default:
			return fmt.Errorf("the entry %q is not a file, a directory, or a link", h.Name)
		}
		if u.root == nil || name == "." {
			continue
		}
		mode := uint32(h.Mode) &^ 0o022 & 0o7777
		switch h.Typeflag {
		case tar.TypeDir:
			err = u.dir(name, mode)
		case tar.TypeReg:
			err = u.file(name, tr, mode)
		case tar.TypeSymlink:
			err = u.symlink(name, h.Linkname)
		case tar.TypeLink:
			err = u.link(name, path.Clean(h.Linkname))
		}
		if err != nil {
			return err
		}
	}
}

func (u unpacker) zip(zr *zip.Reader) error {
	for _, f := range zr.File {
		name, err := entryName(f.Name)
		if err != nil {
			return err
		}
		m := f.Mode()
		if !m.IsDir() && !m.IsRegular() && m&fs.ModeSymlink == 0 {
			return fmt.Errorf("the entry %q is not a file, a directory, or a link", f.Name)
		}
		if u.root == nil || name == "." {
			continue
		}
		mode := uint32(m.Perm()) &^ 0o022
		if m&fs.ModeSetuid != 0 {
			mode |= 0o4000
		}
		if m&fs.ModeSetgid != 0 {
			mode |= 0o2000
		}
		if m&fs.ModeSticky != 0 {
			mode |= 0o1000
		}
		r, err := f.Open()
		if err != nil {
			return fmt.Errorf("the entry %q: %w", f.Name, err)
		}
		switch {
		case m.IsDir():
			err = u.dir(name, mode)
		case m&fs.ModeSymlink != 0:
			var target []byte
			if target, err = io.ReadAll(r); err == nil {
				err = u.symlink(name, string(target))
			}
		default:
			err = u.file(name, r, mode)
		}
		r.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// entryName returns the clean name of an archive entry, which must stay in
// the directory.
func entryName(name string) (string, error) {
	if !filepath.IsLocal(name) {
		return "", fmt.Errorf("the entry %q is outside the directory", name)
	}
	return path.Clean(name), nil
}

// parents creates the missing parent directories of name.
func (u unpacker) parents(name string) error {
	d := path.Dir(name)
	if d == "." {
		return nil
	}
	if fi, err := u.root.Lstat(d); err == nil && fi.IsDir() {
		return nil
	}
	if err := u.parents(d); err != nil {
		return err
	}
	return u.dir(d, 0o755)
}

func (u unpacker) dir(name string, mode uint32) error {
	if err := u.parents(name); err != nil {
		return err
	}
	if err := u.root.Mkdir(name, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	fi, err := u.root.Lstat(name)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is %s, not a directory", path.Join(u.path, name), kind(fi))
	}
	d, err := openRoot(u.root, name, fi)
	if err != nil {
		return err
	}
	defer d.Close()
	return setRootAttrs(d, u.uid, u.gid, mode)
}

// file writes a temporary file and renames it to name, so a running program
// at name keeps its old file.
func (u unpacker) file(name string, r io.Reader, mode uint32) error {
	if err := u.parents(name); err != nil {
		return err
	}
	return writeFile(u.root, name, r, u.uid, u.gid, mode, func(tmp string) error {
		return u.root.Rename(tmp, name)
	})
}

func (u unpacker) symlink(name, target string) error {
	if err := u.replace(name); err != nil {
		return err
	}
	if err := u.root.Symlink(target, name); err != nil {
		return err
	}
	return u.root.Lchown(name, int(u.uid), int(u.gid))
}

func (u unpacker) link(name, target string) error {
	if err := u.replace(name); err != nil {
		return err
	}
	return u.root.Link(target, name)
}

// replace creates the parents of name and removes an entry at name that is
// not a directory.
func (u unpacker) replace(name string) error {
	if err := u.parents(name); err != nil {
		return err
	}
	fi, err := u.root.Lstat(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return err
	case fi.IsDir():
		return fmt.Errorf("%s is a directory", path.Join(u.path, name))
	}
	return u.root.Remove(name)
}
