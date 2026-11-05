package module

import (
	"archive/tar"
	"bytes"
	"cmp"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path"
	"slices"
	"strconv"
	"strings"
)

const (
	dpkgInfo    = "/var/lib/dpkg/info"
	ucfRegistry = "/var/lib/ucf/registry"
	archives    = "/var/cache/apt/archives"
	aptDir      = "/var/lib/winch/apt"
	fetched     = "/var/lib/winch/" + FetchedDir
)

// FetchedDir is the directory in the state directory of the archives that
// stock fetches in a session.
const FetchedDir = "apt/fetched"

// ListsDir is the directory in the state directory of winch's package index.
const ListsDir = "apt/lists"

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
	// content is the archive entry, or the source file of copy_from. It is
	// nil for a source that an earlier step of the run writes.
	content io.ReadSeeker
	// text is the content for the diff, or nil; reason then says why.
	text   *string
	reason string
}

// setText sets the text of the diff from data, the content or its start.
func (h *hostContent) setText(data []byte) {
	if h.reason = notText(data); h.reason == "" {
		h.text = new(string(data))
	}
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

// copySource reads the copy_from source p, as the earlier steps of st leave
// it.
func copySource(ctx context.Context, st *State, p string) (*hostContent, error) {
	h := &hostContent{line: "content from " + p, from: p}
	noSource := func() (*hostContent, error) {
		h.line += " (does not exist yet)"
		h.missing = fmt.Errorf("%s does not exist", p)
		return h, nil
	}
	fromDeb := func(deb *debFile) (*hostContent, error) {
		h.fromArchive(deb)
		h.mode &^= 0o7022
		return h, nil
	}
	src := st.resolve(p)
	for links := 0; ; links++ {
		e, ok := st.planned(src)
		if !ok {
			break
		}
		switch {
		case links > 40:
			return nil, fmt.Errorf("%s: %w", p, errLinkLevels)
		case e.Kind == "link":
			t := e.Target
			if !path.IsAbs(t) {
				t = path.Join(path.Dir(src), t)
			}
			src = st.resolve(t)
		case e.Kind == "dir":
			return nil, fmt.Errorf("%s is a directory, not a file", p)
		case e.Kind == "" || e.SHA256 == "":
			return noSource()
		default:
			h.sum, h.mode = e.SHA256, e.Mode&0o777&^0o022
			return h, nil
		}
	}
	f, fi, err := openSource(src)
	if err != nil && !errors.Is(err, errNoSource) {
		return nil, err
	}
	if len(st.packages()) > 0 {
		deb, perr := plannedSource(ctx, st, src)
		if perr != nil || deb != nil {
			if f != nil {
				f.Close()
			}
			// The new version no longer ships the file.
			if _, ok := errors.AsType[*noEntryError](perr); ok {
				return noSource()
			}
			if h.afterRefresh(perr) {
				return h, nil
			}
			if perr != nil {
				return nil, perr
			}
			return fromDeb(deb)
		}
	}
	if err != nil {
		return noSource()
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

// stockSource reads what the package that owns p ships for p, in the version
// that the earlier steps of st leave installed.
func stockSource(ctx context.Context, st *State, p string) (*hostContent, error) {
	h := &hostContent{line: "content of the package that ships " + p, from: "the package"}
	stock := func(deb *debFile) (*hostContent, error) {
		h.line = "content of " + deb.name + " " + deb.version
		h.fromArchive(deb)
		h.owner = cmp.Or(deb.hdr.Uname, strconv.Itoa(deb.hdr.Uid))
		h.group = cmp.Or(deb.hdr.Gname, strconv.Itoa(deb.hdr.Gid))
		return h, nil
	}
	pkg, err := owner(p)
	if err != nil {
		return nil, err
	}
	var deb *debFile
	if pkg == "" {
		deb, err = shippedFile(ctx, st, p)
	} else {
		deb, err = upgradedFile(ctx, st, pkg, p, false)
	}
	if h.afterRefresh(err) {
		return h, nil
	}
	if err != nil {
		return nil, err
	}
	if deb != nil {
		return stock(deb)
	}
	const noPackage = " (no installed package ships it yet)"
	if pkg == "" {
		registry, err := os.ReadFile(ucfRegistry)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		if pkg = ucfOwner(registry, p); pkg != "" {
			return nil, fmt.Errorf("%s makes %s with ucf and ships no copy; use copy_from with its source in /usr/share", pkg, p)
		}
		h.line += noPackage
		h.missing = fmt.Errorf("no installed package ships %s; install its package in an earlier pkg step, or use copy_from for a file that a package script makes", p)
		return h, nil
	}
	out, err := run(ctx, "dpkg-query", "-W", "-f=${Version}\t${Architecture}\t${db:Status-Abbrev}", pkg)
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
		h.line += noPackage
		h.missing = fmt.Errorf("%s is not installed, so no installed package ships %s; install it in an earlier pkg step", pkg, p)
		return h, nil
	}
	if deb, err = fetchFile(ctx, pkg, PlannedPkg{Version: version, Arch: arch}, p); err != nil {
		return nil, err
	}
	return stock(deb)
}

// debFile is a file of a package archive.
type debFile struct {
	name, version string
	data          []byte
	hdr           *tar.Header
}

// fromArchive sets the content and the mode of h from the archive file.
func (h *hostContent) fromArchive(deb *debFile) {
	h.content, h.sum = bytes.NewReader(deb.data), sha(deb.data)
	h.mode = uint32(deb.hdr.Mode) & 0o7777
	h.setText(deb.data)
}

// afterRefresh reports whether err is an afterRefreshError, and then makes h
// content that the plan does not know yet.
func (h *hostContent) afterRefresh(err error) bool {
	_, ok := errors.AsType[*afterRefreshError](err)
	if ok {
		h.line += " (known after the refresh)"
		h.missing = err
	}
	return ok
}

// plannedSource returns the copy_from source p from the archive of the
// version that an earlier step installs, or nil when the host keeps its own
// p. A source that no installed package owns comes from a package that an
// earlier pkg step names.
func plannedSource(ctx context.Context, st *State, p string) (*debFile, error) {
	pkg, err := owner(p)
	if err != nil {
		return nil, err
	}
	if pkg == "" {
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return shippedFile(ctx, st, p)
	}
	deb, err := upgradedFile(ctx, st, pkg, p, true)
	if _, ok := errors.AsType[*notFileError](err); ok {
		// The host follows the link that the package ships.
		return nil, nil
	}
	return deb, err
}

// owner returns the installed package that owns p, or "".
func owner(p string) (string, error) {
	owners, err := dpkgOwners(os.DirFS(dpkgInfo), map[string]bool{p: true})
	return owners[p], err
}

// packages returns the planned packages of st, also of a nil st.
func (st *State) packages() map[string]PlannedPkg {
	if st == nil {
		return nil
	}
	return st.Packages
}

// upgradedFile returns the file p of the version of pkg, the installed
// package that owns p, that an earlier pkg or upgrade step of st installs, or
// nil when no such step changes pkg. With conffiles, a conffile that the host
// changed or removed stays, as dpkg keeps it.
func upgradedFile(ctx context.Context, st *State, pkg, p string, conffiles bool) (*debFile, error) {
	name, _, _ := strings.Cut(pkg, ":")
	pp, ok := st.packages()[name]
	if !ok {
		return nil, nil
	}
	// A half-done package keeps its version.
	installed, err := run(ctx, "dpkg-query", "-W", "-f=${Version}", pkg)
	if err != nil || installed == pp.Version {
		return nil, err
	}
	if conffiles {
		kept, err := keptConffile(ctx, pkg, p)
		if err != nil || kept {
			return nil, err
		}
	}
	return fetchFile(ctx, name, pp, p)
}

// shippedFile returns the file p of the first package that an earlier pkg
// step of st names and that ships p, or nil when none does. An archive that it
// cannot fetch before the refresh can hold p, so without a package that ships
// p, it returns the afterRefreshError of that archive.
func shippedFile(ctx context.Context, st *State, p string) (*debFile, error) {
	pkgs := st.packages()
	var unknown error
	for _, name := range slices.Sorted(maps.Keys(pkgs)) {
		if !pkgs[name].Named {
			continue
		}
		deb, err := fetchFile(ctx, name, pkgs[name], p)
		_, none := errors.AsType[*noEntryError](err)
		_, other := errors.AsType[*notFileError](err)
		if none || other {
			continue
		}
		if _, ok := errors.AsType[*afterRefreshError](err); ok {
			unknown = err
			continue
		}
		return deb, err
	}
	return nil, unknown
}

// fetchFile returns the file p of the archive of version pp of the package
// pkg, which can name its architecture.
func fetchFile(ctx context.Context, pkg string, pp PlannedPkg, p string) (*debFile, error) {
	name, _, _ := strings.Cut(pkg, ":")
	deb, err := archive(ctx, pkg, pp.Version, archiveName(name, pp.Version, pp.Arch), pp.Index)
	if err != nil {
		return nil, fmt.Errorf("get the archive of %s %s: %w", name, pp.Version, err)
	}
	data, hdr, err := debEntry(ctx, deb, p)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", name, pp.Version, err)
	}
	return &debFile{name: name, version: pp.Version, data: data, hdr: hdr}, nil
}

// keptConffile reports whether p is a conffile of the installed package pkg
// that the host changed or removed.
func keptConffile(ctx context.Context, pkg, p string) (bool, error) {
	out, err := run(ctx, "dpkg-query", "-W", "-f=${Conffiles}", pkg)
	if err != nil {
		return false, err
	}
	for line := range strings.SplitSeq(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != p {
			continue
		}
		data, err := os.ReadFile(p)
		if errors.Is(err, fs.ErrNotExist) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		sum := md5.Sum(data)
		return hex.EncodeToString(sum[:]) != f[1], nil
	}
	return false, nil
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

// archive returns the path of the archive file of version of pkg: in apt's
// cache, or in the directory of the session. It fetches a missing archive
// into the directory of the session, so the plan leaves apt's cache as it is.
// A nil index is the version that dpkg reports. apt's own index lacks that
// version after an install from winch's index, so the fetch then also tries
// winch's index.
func archive(ctx context.Context, pkg, version, file string, index []string) (string, error) {
	for _, dir := range []string{archives, fetched} {
		deb := path.Join(dir, file)
		_, err := os.Stat(deb)
		if err == nil {
			return deb, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
	}
	deb := path.Join(fetched, file)
	if err := os.MkdirAll(fetched, 0o700); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeoutCause(ctx, commandLimit, noResult(commandLimit))
	defer cancel()
	err := download(ctx, pkg, version, deb, index)
	if err == nil {
		return deb, nil
	}
	if ctx.Err() != nil {
		return "", err
	}
	if slices.Equal(index, noBinaryCache) {
		return "", &afterRefreshError{err}
	}
	if index != nil {
		return "", err
	}
	if _, serr := os.Stat(winchLists); serr != nil {
		return "", err
	}
	if werr := download(ctx, pkg, version, deb, winchIndex); werr != nil {
		return "", fmt.Errorf("%w; through winch's index: %w", err, werr)
	}
	return deb, nil
}

// download fetches the archive of version of pkg to deb, in the directory of
// the session.
func download(ctx context.Context, pkg, version, deb string, index []string) error {
	cmd := exec.CommandContext(ctx, "apt-get", slices.Concat([]string{"download", "-q", "-o", "APT::Sandbox::User=root"}, noBinaryCache, index, []string{pkg + "=" + version})...)
	cmd.Dir = fetched
	cmd.Env = append(cmd.Environ(), aptEnv...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := wait(ctx, cmd, KillDelay); err != nil {
		// apt-get download writes to the final name as data arrives.
		_ = os.Remove(deb)
		return failure("apt-get download", err, out.String())
	}
	return nil
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
			return nil, nil, &noEntryError{p}
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
			return nil, nil, &notFileError{p, "a directory"}
		case tar.TypeSymlink:
			return nil, nil, &notFileError{p, "a symbolic link"}
		}
		return nil, nil, &notFileError{p, "a special entry"}
	}
}

// afterRefreshError is the error of a failed fetch of a version from apt's
// own index. The refresh at apply can replace that version.
type afterRefreshError struct{ error }

// notFileError is the error of a package archive that has p as another kind
// of entry than a file.
type notFileError struct{ p, kind string }

func (e *notFileError) Error() string {
	return "the archive has " + e.p + " as " + e.kind + ", not a file"
}

// noEntryError is the error of a package archive without the file p.
type noEntryError struct{ p string }

func (e *noEntryError) Error() string { return "the archive has no " + e.p }

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
