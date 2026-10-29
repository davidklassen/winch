package vmtest

import (
	"bufio"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Ubuntu has a group admin, so useradd cannot create the user's own group.
// cloud-init creates a missing group of groups, but not a primary_group.
const userData = `#cloud-config
users:
  - name: admin
    primary_group: admin
    groups: [admin]
    no_user_group: true
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys: [%[1]q]
  - name: nosudo
    shell: /bin/bash
    ssh_authorized_keys: [%[1]q]
ssh_pwauth: false
runcmd:
  - systemctl disable --now $(systemctl list-unit-files --no-legend 'apt-*.timer' | cut -d' ' -f1)
  - systemctl stop 'apt-*.service'
`

const metaData = "instance-id: base\nlocal-hostname: base\n"

// The SSH key of the lab's users. examples/demo names the public key.
var (
	//go:embed testdata/fake_secrets/key
	privateKey []byte
	//go:embed testdata/fake_secrets/key.pub
	PublicKey string
)

func seedUserData() string {
	return fmt.Sprintf(userData, strings.TrimSpace(PublicKey))
}

type snapshotInputs struct {
	Image, Seed, QEMU, Flags string
}

// snapshotName names the snapshot of a platform, such as debian-13-arm64.
func snapshotName(platform string, in snapshotInputs) string {
	return "snapshot-" + platform + "-" + hashParts(in.Image, in.Seed, in.QEMU, in.Flags)
}

// hashParts hashes each part with its length, so no text can move from one
// part to the next.
func hashParts(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		fmt.Fprintf(h, "%d:%s", len(p), p)
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

func (l *Lab) snapshotInputs(ctx context.Context) (snapshotInputs, error) {
	f, err := os.Open(l.cfg.Image)
	if err != nil {
		return snapshotInputs{}, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return snapshotInputs{}, err
	}
	args, err := qemuArgs(l.Arch, "DISK", "DIR", ports{}, true)
	if err != nil {
		return snapshotInputs{}, err
	}
	version, err := exec.CommandContext(ctx, args[0], "--version").Output()
	if err != nil {
		return snapshotInputs{}, fmt.Errorf("%s --version: %w", args[0], err)
	}
	return snapshotInputs{
		Image: hex.EncodeToString(h.Sum(nil)),
		Seed:  seedUserData() + metaData,
		QEMU:  strings.SplitN(string(version), "\n", 2)[0],
		Flags: strings.Join(append(args, "disk "+diskSize), "\n"),
	}, nil
}

// ensureSnapshot finds the snapshot of the lab's inputs in the cache, or
// builds it.
func (l *Lab) ensureSnapshot(ctx context.Context) error {
	in, err := l.snapshotInputs(ctx)
	if err != nil {
		return err
	}
	l.snapshot = snapshotName(l.platform(), in)
	if err := l.useKey(); err != nil {
		return err
	}
	dir := filepath.Join(l.cfg.Cache, l.snapshot)
	_, err = os.Stat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return l.buildSnapshot(ctx, dir)
	}
	return err
}

// useKey gives the lab the SSH key, and serves the seed with it. A reboot of
// a VM reads the seed again; with the same instance-id, cloud-init does not
// run again.
func (l *Lab) useKey() error {
	if err := os.WriteFile(filepath.Join(l.Dir, "key"), privateKey, 0o600); err != nil {
		return err
	}
	seed := map[string]string{
		"meta-data":   metaData,
		"user-data":   seedUserData(),
		"vendor-data": "",
	}
	for name, content := range seed {
		if err := os.WriteFile(filepath.Join(l.Dir, "www", "seed", name), []byte(content), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// buildSnapshot boots a VM from the image, waits for cloud-init, and saves
// the machine.
func (l *Lab) buildSnapshot(ctx context.Context, dir string) error {
	fmt.Fprintf(os.Stderr, "vmtest: building the VM snapshot %s\n", dir)
	tmp, err := os.MkdirTemp(l.cfg.Cache, "tmp-snapshot-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	vm, err := l.boot(ctx, "base", tmp, l.cfg.Image, true, "")
	if err != nil {
		return err
	}
	defer vm.Stop()
	if err := vm.waitBoot(ctx); err != nil {
		return err
	}
	if err := vm.save(ctx, filepath.Join(tmp, "state")); err != nil {
		return err
	}
	// QEMU must be gone before the rename.
	vm.Stop()
	if err := os.Rename(tmp, dir); err != nil {
		// Another process has built the snapshot first.
		if _, serr := os.Stat(dir); serr == nil {
			return nil
		}
		return err
	}
	return removeOthers(l.cfg.Cache, "snapshot-"+l.platform()+"-", dir)
}

// save stops the VM, writes its machine state to path with a migration, and
// quits QEMU. A migration of a running VM crashes QEMU with HVF.
func (vm *VM) save(ctx context.Context, path string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	q, err := dialQMP(ctx, vm.qmpPort, vm.exited)
	if err != nil {
		return err
	}
	defer q.Close() //nolint:errcheck // the answers are read
	if err := q.call("stop", nil, nil); err != nil {
		return err
	}
	if err := q.call("migrate", map[string]string{"uri": "file:" + path}, nil); err != nil {
		return err
	}
	for {
		var st struct {
			Status    string
			ErrorDesc string `json:"error-desc"`
		}
		if err := q.call("query-migrate", nil, &st); err != nil {
			return err
		}
		switch st.Status {
		case "completed":
			// QEMU on Linux can close the connection before it answers quit.
			err := q.call("quit", nil, nil)
			select {
			case <-vm.exited:
				return nil
			case <-ctx.Done():
				return errors.Join(err, fmt.Errorf("quit QEMU: %w", ctx.Err()))
			}
		case "failed", "cancelled":
			return fmt.Errorf("save the VM: %s %s", st.Status, st.ErrorDesc)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("save the VM: %w", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// removeOthers removes the entries of dir with the prefix, except keep.
func removeOthers(dir, prefix, keep string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		if strings.HasPrefix(e.Name(), prefix) && path != keep {
			if err := os.RemoveAll(path); err != nil {
				return err
			}
		}
	}
	return nil
}

// qmp is a client of the QEMU Machine Protocol.
type qmp struct {
	conn net.Conn
	r    *bufio.Reader
}

// dialQMP connects to QEMU's QMP port. QEMU opens it soon after its start.
func dialQMP(ctx context.Context, port int, exited <-chan struct{}) (*qmp, error) {
	var d net.Dialer
	for {
		conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			q := &qmp{conn: conn, r: bufio.NewReader(conn)}
			if _, err := q.r.ReadString('\n'); err != nil {
				conn.Close() //nolint:errcheck // the handshake failed already
				return nil, fmt.Errorf("qmp greeting: %w", err)
			}
			if err := q.call("qmp_capabilities", nil, nil); err != nil {
				conn.Close() //nolint:errcheck // the handshake failed already
				return nil, err
			}
			return q, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("qmp: %w", err)
		case <-exited:
			return nil, errors.New("qemu exited")
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func (q *qmp) call(command string, args, result any) error {
	msg := map[string]any{"execute": command}
	if args != nil {
		msg["arguments"] = args
	}
	req, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if _, err := q.conn.Write(append(req, '\n')); err != nil {
		return fmt.Errorf("qmp %s: %w", command, err)
	}
	for {
		line, err := q.r.ReadBytes('\n')
		if err != nil {
			return fmt.Errorf("qmp %s: %w", command, err)
		}
		var resp struct {
			Event  string
			Return json.RawMessage
			Error  *struct{ Desc string }
		}
		if err := json.Unmarshal(line, &resp); err != nil {
			return fmt.Errorf("qmp %s: %w", command, err)
		}
		switch {
		case resp.Event != "":
			continue
		case resp.Error != nil:
			return fmt.Errorf("qmp %s: %s", command, resp.Error.Desc)
		case result != nil:
			return json.Unmarshal(resp.Return, result)
		}
		return nil
	}
}

func (q *qmp) Close() error {
	return q.conn.Close()
}
