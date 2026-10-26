package vmtest

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
)

// repoInput is a tar of the repository definition: the package lists and the
// package definitions. It names the repository and goes to the VM that fills
// it.
func repoInput(defs fs.FS) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := writeTree(tw, defs); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func repoName(arch, snapshot string, input []byte) string {
	return "repo-" + arch + "-" + hashParts(snapshot, string(input), fillScript)
}

// ensureRepo finds the repository of the lab's inputs in the cache, or
// builds it, and serves it from the lab's HTTP server.
func (l *Lab) ensureRepo(ctx context.Context) error {
	input, err := repoInput(os.DirFS(l.cfg.Repo))
	if err != nil {
		return err
	}
	dir := filepath.Join(l.cfg.Cache, repoName(l.Arch, l.snapshot, input))
	if _, err := os.Stat(dir); l.cfg.Refresh || errors.Is(err, os.ErrNotExist) {
		if err := l.buildRepo(ctx, dir, input); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	for _, part := range []string{"debian", "test", "signed"} {
		if err := os.Symlink(filepath.Join(dir, part), filepath.Join(l.Dir, "www", part)); err != nil {
			return err
		}
	}
	return nil
}

// fillScript downloads each listed package with the dependencies that the
// VM lacks, one at a time, so packages that conflict all arrive. It builds
// the test packages and writes an index for each part. The part signed holds
// the packages of signed.list and of signed/, in a suite trixie with a signed
// InRelease. It also holds the public key of the suite as key.asc, key.gpg
// (binary), and key.fpr (the fingerprint), and an unrelated key as other.asc
// and other.fpr.
const fillScript = `set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -q >/dev/null
for p in $(sed 's/#.*//' /root/defs/debian.list /root/defs/signed.list); do
	apt-get install -q -y --download-only --reinstall "$p" >/dev/null
done
mkdir -p /root/repo/debian/pool /root/repo/test/pool /root/repo/signed/pool
for p in $(sed 's/#.*//' /root/defs/signed.list); do
	mv /var/cache/apt/archives/"$p"_*.deb /root/repo/signed/pool/
done
cp /var/cache/apt/archives/*.deb /root/repo/debian/pool/
for d in /root/defs/packages/*/; do
	dpkg-deb -b "$d" /root/repo/test/pool/ >/dev/null
done
for d in /root/defs/signed/*/; do
	dpkg-deb -b "$d" /root/repo/signed/pool/ >/dev/null
done
for part in debian test; do
	cd /root/repo/$part
	apt-ftparchive packages pool > Packages
done
apt-get install -q -y gnupg >/dev/null
arch=$(dpkg --print-architecture)
cd /root/repo/signed
mkdir -p dists/trixie/main/binary-$arch
apt-ftparchive packages pool > dists/trixie/main/binary-$arch/Packages
apt-ftparchive -o APT::FTPArchive::Release::Suite=trixie -o APT::FTPArchive::Release::Codename=trixie \
	-o APT::FTPArchive::Release::Components=main -o APT::FTPArchive::Release::Architectures=$arch \
	release dists/trixie > /root/Release
mv /root/Release dists/trixie/Release
export GNUPGHOME=$(mktemp -d)
gpg --batch -q --passphrase '' --quick-gen-key 'winch test repository' ed25519 sign never 2>/dev/null
gpg --batch -q --passphrase '' --quick-gen-key 'winch other key' ed25519 sign never 2>/dev/null
gpg --batch -q -u 'winch test repository' --clearsign -o dists/trixie/InRelease dists/trixie/Release
gpg --armor --export 'winch test repository' > key.asc
gpg --export 'winch test repository' > key.gpg
gpg --armor --export 'winch other key' > other.asc
gpg --with-colons --list-keys 'winch test repository' | awk -F: '/^fpr/ {print $10; exit}' > key.fpr
gpg --with-colons --list-keys 'winch other key' | awk -F: '/^fpr/ {print $10; exit}' > other.fpr
cd /root/repo
tar -c .
`

// buildRepo fills the repository in an online VM from the snapshot and
// copies it into the cache.
func (l *Lab) buildRepo(ctx context.Context, dir string, input []byte) error {
	fmt.Fprintf(os.Stderr, "vmtest: building the apt repository %s\n", dir)
	vm, err := l.clone(ctx, "fill", true)
	if err != nil {
		return err
	}
	defer vm.Stop()
	if err := vm.stream(ctx, "mkdir -p /root/defs && tar -x -C /root/defs", bytes.NewReader(input), io.Discard); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(l.cfg.Cache, "tmp-repo-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	archive, err := os.Create(filepath.Join(vm.dir, "repo.tar"))
	if err != nil {
		return err
	}
	err = vm.stream(ctx, fillScript, nil, archive)
	if cerr := archive.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if out, err := exec.CommandContext(ctx, "tar", "-x", "-C", tmp, "-f", archive.Name()).CombinedOutput(); err != nil {
		return fmt.Errorf("tar: %v: %s", err, out)
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.Rename(tmp, dir); err != nil {
		// Another process has built the repository first.
		if _, serr := os.Stat(dir); serr == nil {
			return nil
		}
		return err
	}
	return removeOthers(l.cfg.Cache, "repo-"+l.Arch+"-", dir)
}

// writeTree writes the files of fsys to tw below ".", as root, with mode 0755
// for an executable file and for a directory, else 0644.
func writeTree(tw *tar.Writer, fsys fs.FS) error {
	return fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == "." {
			return nil
		}
		name := "./" + path
		if d.IsDir() {
			return tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: name + "/", Mode: 0o755})
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		mode := int64(0o644)
		if info.Mode()&0o111 != 0 {
			mode = 0o755
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(data))}); err != nil {
			return err
		}
		_, err = tw.Write(data)
		return err
	})
}
