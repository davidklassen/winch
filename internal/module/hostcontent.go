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
	deb, perr := plannedEntry(ctx, st, src)
	if perr == nil && deb != nil && deb.file() != nil {
		// The host follows the link that the package ships.
		deb = nil
	}
	if perr != nil || deb != nil {
		if f != nil {
			f.Close()
		}
		// The new version no longer ships the file.
		if _, ok := errors.AsType[*noEntryError](perr); ok {
			return noSource()
		}
		if perr != nil {
			return nil, perr
		}
		return fromDeb(deb)
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
	h := &hostContent{line: "content of the package that ships " + p + " (no installed package ships it yet)", from: "the package"}
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
	deb, err := upgraded(ctx, st, pkg, p, false)
	if err == nil && deb != nil {
		err = deb.file()
	}
	if err != nil {
		return nil, err
	}
	if deb != nil {
		return stock(deb)
	}
	if pkg == "" {
		deb, err := shipped(ctx, st, p)
		if err != nil {
			return nil, err
		}
		if deb != nil && deb.file() == nil {
			return stock(deb)
		}
		registry, err := os.ReadFile(ucfRegistry)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		if pkg = ucfOwner(registry, p); pkg != "" {
			return nil, fmt.Errorf("%s makes %s with ucf and ships no copy; use copy_from with its source in /usr/share", pkg, p)
		}
		h.missing = fmt.Errorf("no installed package ships %s; install its package in an earlier pkg step, or use copy_from for a file that a package script makes", p)
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
		h.missing = fmt.Errorf("%s is not installed, so no installed package ships %s; install it in an earlier pkg step", pkg, p)
		return h, nil
	}
	if deb, err = fetchEntry(ctx, pkg, PlannedPkg{Version: version, Arch: arch}, p); err != nil {
		return nil, err
	}
	if err := deb.file(); err != nil {
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

// plannedEntry returns the entry that an earlier pkg or upgrade step of st
// puts at p, or nil when the host keeps what it has at p. A conffile that the
// host changed or removed stays, as dpkg keeps it. A path that no planned
// package owns comes from a package that an earlier pkg step names. The error
// is a noEntryError when the new version drops p.
func plannedEntry(ctx context.Context, st *State, p string) (*debFile, error) {
	if len(st.packages()) == 0 {
		return nil, nil
	}
	pkg, err := plannedOwner(st, p)
	if err != nil {
		return nil, err
	}
	if pkg != "" {
		return upgraded(ctx, st, pkg, p, true)
	}
	if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return shipped(ctx, st, p)
}

// plannedOwner returns the package of st.Packages that is installed and owns
// p, or "". It reads only the file lists of those packages.
func plannedOwner(st *State, p string) (string, error) {
	pkgs := st.packages()
	for _, name := range slices.Sorted(maps.Keys(pkgs)) {
		for _, pkg := range []string{name, name + ":" + pkgs[name].Arch} {
			data, err := os.ReadFile(path.Join(dpkgInfo, pkg+".list"))
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return "", err
			}
			for line := range bytes.Lines(data) {
				if string(bytes.TrimSuffix(line, []byte("\n"))) == p {
					return pkg, nil
				}
			}
		}
	}
	return "", nil
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

// upgraded returns the entry p of the version of pkg, the installed package
// that owns p, that an earlier pkg or upgrade step of st installs, or nil when
// no such step changes pkg. With conffiles, a conffile that the host changed
// or removed stays, as dpkg keeps it.
func upgraded(ctx context.Context, st *State, pkg, p string, conffiles bool) (*debFile, error) {
	name, _, _ := strings.Cut(pkg, ":")
	pp, ok := st.packages()[name]
	if pkg == "" || !ok {
		return nil, nil
	}
	var sum string
	if conffiles {
		var kept bool
		var err error
		if kept, sum, err = keptConffile(ctx, pkg, p); err != nil || kept {
			return nil, err
		}
	}
	deb, err := fetchEntry(ctx, name, pp, p)
	if err != nil {
		return nil, err
	}
	// dpkg leaves a conffile that the new version does not change, with its
	// owner and mode.
	if got := md5.Sum(deb.data); sum == hex.EncodeToString(got[:]) {
		return nil, nil
	}
	return deb, nil
}

// shipped returns the entry p of the first package that an earlier pkg step
// of st names and that ships p, or nil when none does.
func shipped(ctx context.Context, st *State, p string) (*debFile, error) {
	pkgs := st.packages()
	for _, name := range slices.Sorted(maps.Keys(pkgs)) {
		if !pkgs[name].Named {
			continue
		}
		deb, err := fetchEntry(ctx, name, pkgs[name], p)
		if _, none := errors.AsType[*noEntryError](err); none {
			continue
		}
		if ae, ok := errors.AsType[*archiveError](err); ok {
			ae.search = true
		}
		return deb, err
	}
	return nil, nil
}

// packaged is plannedEntry for a step on its own path p, when the entry has
// kind, a tar type flag.
func packaged(ctx context.Context, st *State, p string, kind byte) (*debFile, error) {
	deb, err := plannedEntry(ctx, st, p)
	if _, ok := errors.AsType[*noEntryError](err); ok {
		// A path that the new version drops reads from the host. dpkg
		// removes such a file, but keeps a conffile.
		return nil, nil
	}
	if ae, ok := errors.AsType[*archiveError](err); ok && ae.search {
		// The check of a pkg step can read an index older than the refresh of
		// its apply, so apt can lack the version. A path that the package may
		// not ship must not fail the plan.
		return nil, nil
	}
	if err != nil || deb == nil || deb.hdr.Typeflag != kind {
		return nil, err
	}
	return deb, nil
}

// fetchEntry returns the entry p of the archive of version pp of the package
// pkg, which can name its architecture.
func fetchEntry(ctx context.Context, pkg string, pp PlannedPkg, p string) (*debFile, error) {
	name, _, _ := strings.Cut(pkg, ":")
	deb, err := archive(ctx, pkg, pp.Version, archiveName(name, pp.Version, pp.Arch), pp.Index)
	if err != nil {
		return nil, &archiveError{err: fmt.Errorf("get the archive of %s %s: %w", name, pp.Version, err)}
	}
	data, hdr, err := listedEntry(ctx, deb, p)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", name, pp.Version, err)
	}
	return &debFile{name: name, version: pp.Version, data: data, hdr: hdr}, nil
}

// file returns an error when the entry is no file.
func (d *debFile) file() error {
	kind := "a special entry"
	switch d.hdr.Typeflag {
	case tar.TypeReg:
		return nil
	case tar.TypeDir:
		kind = "a directory"
	case tar.TypeSymlink:
		kind = "a symbolic link"
	}
	return fmt.Errorf("%s %s: %w", d.name, d.version, &notFileError{entryPath(d.hdr), kind})
}

// info returns the info of the entry as dpkg unpacks it on the host.
// dpkg takes the owner and group by name when the host has the name.
func (d *debFile) info() (fs.FileInfo, error) {
	uid, gid := d.hdr.Uid, d.hdr.Gid
	if d.hdr.Uname != "" {
		id, ok, err := lookupUser(d.hdr.Uname)
		if err != nil {
			return nil, err
		}
		if ok {
			uid = id
		}
	}
	if d.hdr.Gname != "" {
		id, ok, err := lookupGroup(d.hdr.Gname)
		if err != nil {
			return nil, err
		}
		if ok {
			gid = id
		}
	}
	return &entryInfo{d.hdr.FileInfo(), uint32(uid), uint32(gid), uint32(d.hdr.Mode) & 0o7777}, nil
}

// entryInfo is the info of an archive entry that an earlier step unpacks.
type entryInfo struct {
	fs.FileInfo
	uid, gid, mode uint32
}

// listedEntry is debEntry with the list of the archive's paths, which it
// keeps in the directory of the session. The first read of an archive reads
// all of it and writes the list. A later read of a path that the list does
// not have does not read the archive.
func listedEntry(ctx context.Context, deb, p string) ([]byte, *tar.Header, error) {
	list := path.Join(fetched, path.Base(deb)+".paths")
	paths, err := os.ReadFile(list)
	switch {
	case err == nil && !bytes.Contains(paths, []byte("\n"+p+"\n")):
		return nil, nil, &noEntryError{p}
	case err == nil:
		return debEntry(ctx, deb, p)
	case !errors.Is(err, fs.ErrNotExist):
		return nil, nil, err
	}
	var data []byte
	var hdr *tar.Header
	b := bytes.NewBufferString("\n")
	err = readFsys(ctx, deb, func(tr *tar.Reader) error {
		for {
			h, err := tr.Next()
			if err != nil {
				return err
			}
			b.WriteString(entryPath(h) + "\n")
			if entryPath(h) != p {
				continue
			}
			if hdr = h; h.Typeflag == tar.TypeReg {
				if data, err = io.ReadAll(tr); err != nil {
					return err
				}
			}
		}
	})
	if err != io.EOF {
		return nil, nil, err
	}
	if err := os.MkdirAll(fetched, 0o700); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(list, b.Bytes(), 0o600); err != nil {
		return nil, nil, err
	}
	if hdr == nil {
		return nil, nil, &noEntryError{p}
	}
	return data, hdr, nil
}

// keptConffile reports whether p is a conffile of the installed package pkg
// that the host changed or removed. sum is the md5 that dpkg records for a
// conffile, or "".
func keptConffile(ctx context.Context, pkg, p string) (kept bool, sum string, err error) {
	out, err := run(ctx, nil, "dpkg-query", "-W", "-f=${Conffiles}", pkg)
	if err != nil {
		return false, "", err
	}
	for line := range strings.SplitSeq(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != p {
			continue
		}
		h, _, err := openSource(p)
		if errors.Is(err, errNoSource) {
			return true, f[1], nil
		}
		if err != nil {
			return false, "", err
		}
		defer h.Close()
		hash := md5.New()
		if _, err := io.Copy(hash, h); err != nil {
			return false, "", fmt.Errorf("read %s: %w", p, err)
		}
		return hex.EncodeToString(hash.Sum(nil)) != f[1], f[1], nil
	}
	return false, "", nil
}

// debEntry returns the header of the entry p in the package archive deb, and
// the content of a file. It stops at p.
func debEntry(ctx context.Context, deb, p string) ([]byte, *tar.Header, error) {
	var data []byte
	var hdr *tar.Header
	err := readFsys(ctx, deb, func(tr *tar.Reader) error {
		var err error
		data, hdr, err = tarEntry(tr, p)
		return err
	})
	return data, hdr, err
}

// readFsys runs read on the data archive of the package archive deb, as
// dpkg-deb unpacks it. read can stop before the end.
func readFsys(ctx context.Context, deb string, read func(*tar.Reader) error) error {
	cmd := exec.CommandContext(ctx, "dpkg-deb", "--fsys-tarfile", deb)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.WaitDelay = KillDelay
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	err = read(tar.NewReader(out))
	if err == nil {
		// The processes of dpkg-deb, also its decompressor, end on the
		// closed pipe.
		_ = out.Close()
		_ = cmd.Wait()
		return nil
	}
	// dpkg-deb runs to its end, so Wait gets its own error.
	_, _ = io.Copy(io.Discard, out)
	if werr := cmd.Wait(); werr != nil {
		return failure("dpkg-deb", werr, stderr.String())
	}
	return err
}

// archive returns the path of the archive file of version of pkg: in apt's
// cache, or in the directory of the session. It fetches a missing archive
// into the directory of the session, so the plan leaves apt's cache as it is.
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
	cmd := exec.CommandContext(ctx, "apt-get", slices.Concat([]string{"download", "-q", "-o", "APT::Sandbox::User=root"}, noBinaryCache, index, []string{pkg + "=" + version})...)
	cmd.Dir = fetched
	cmd.Env = append(cmd.Environ(), aptEnv...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := wait(ctx, cmd, KillDelay); err != nil {
		// apt-get download writes to the final name as data arrives.
		_ = os.Remove(deb)
		return "", failure("apt-get download", err, out.String())
	}
	return deb, nil
}

// archiveName is the name of a package archive in apt's cache.
func archiveName(pkg, version, arch string) string {
	return pkg + "_" + strings.ReplaceAll(version, ":", "%3a") + "_" + arch + ".deb"
}

// tarEntry returns the header of the entry p in the data archive of a
// package, and the content of a file.
func tarEntry(tr *tar.Reader, p string) ([]byte, *tar.Header, error) {
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil, nil, &noEntryError{p}
		}
		if err != nil {
			return nil, nil, err
		}
		if entryPath(hdr) != p {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, hdr, nil
		}
		data, err := io.ReadAll(tr)
		return data, hdr, err
	}
}

// entryPath is the path on the host of an entry of the data archive of a
// package.
func entryPath(hdr *tar.Header) string {
	return strings.TrimSuffix(strings.TrimPrefix(hdr.Name, "."), "/")
}

// notFileError is the error of a package archive that has p as another kind
// of entry than a file.
type notFileError struct{ p, kind string }

func (e *notFileError) Error() string {
	return "the archive has " + e.p + " as " + e.kind + ", not a file"
}

// archiveError is the error of a package archive that apt cannot fetch. search
// is set when the archive came up in a search for a path that no installed
// package owns.
type archiveError struct {
	err    error
	search bool
}

func (e *archiveError) Error() string { return e.err.Error() }

func (e *archiveError) Unwrap() error { return e.err }

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
