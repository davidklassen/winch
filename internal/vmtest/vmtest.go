// Package vmtest starts Debian VMs in QEMU for integration tests. A Lab holds
// the test SSH key and an ssh wrapper that reads the lab's SSH config, so
// winch and the tests reach each VM by its name.
package vmtest

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Lab struct {
	Dir   string
	Image string
	Arch  string
	// PATH has the ssh wrapper first.
	PATH   string
	pubKey string
}

// NewLab prepares dir: a key, the SSH config, and the ssh wrapper.
func NewLab(ctx context.Context, dir, image, arch string) (*Lab, error) {
	if _, err := os.Stat(image); err != nil {
		return nil, fmt.Errorf("vm image: %w (run make vm-image)", err)
	}
	key := filepath.Join(dir, "key")
	if out, err := exec.CommandContext(ctx, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("ssh-keygen: %v: %s", err, out)
	}
	pub, err := os.ReadFile(key + ".pub")
	if err != nil {
		return nil, err
	}
	for _, d := range []string{"bin", "hosts", "vms"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			return nil, err
		}
	}
	config := fmt.Sprintf(`Include %s/hosts/*.conf
Host *
  User admin
  IdentityFile %s
  IdentitiesOnly yes
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  LogLevel ERROR
  ConnectTimeout 5
`, dir, key)
	if err := os.WriteFile(filepath.Join(dir, "ssh_config"), []byte(config), 0o644); err != nil {
		return nil, err
	}
	wrapper := fmt.Sprintf("#!/bin/sh\nexec /usr/bin/ssh -F %s/ssh_config \"$@\"\n", dir)
	if err := os.WriteFile(filepath.Join(dir, "bin", "ssh"), []byte(wrapper), 0o755); err != nil {
		return nil, err
	}
	return &Lab{
		Dir:    dir,
		Image:  image,
		Arch:   arch,
		PATH:   filepath.Join(dir, "bin") + ":" + os.Getenv("PATH"),
		pubKey: strings.TrimSpace(string(pub)),
	}, nil
}

// Env returns the environment of this process with the lab's PATH.
func (l *Lab) Env() []string {
	var env []string
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "PATH=") {
			env = append(env, e)
		}
	}
	return append(env, "PATH="+l.PATH)
}

type VM struct {
	Name   string
	lab    *Lab
	dir    string
	cmd    *exec.Cmd
	exited chan struct{}
	seed   *http.Server
}

const userData = `#cloud-config
users:
  - name: admin
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys: [%[1]q]
  - name: nosudo
    shell: /bin/bash
    ssh_authorized_keys: [%[1]q]
ssh_pwauth: false
`

// Start boots a VM from a copy-on-write layer over the image and waits until
// cloud-init is done.
func (l *Lab) Start(ctx context.Context, name string) (_ *VM, err error) {
	vm := &VM{Name: name, lab: l, dir: filepath.Join(l.Dir, "vms", name)}
	defer func() {
		if err != nil {
			vm.Stop()
		}
	}()
	if err := os.MkdirAll(vm.dir, 0o755); err != nil {
		return nil, err
	}
	disk := filepath.Join(vm.dir, "disk.qcow2")
	if out, err := exec.CommandContext(ctx, "qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", l.Image, disk).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("qemu-img: %v: %s", err, out)
	}
	seed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	files := map[string]string{
		"/meta-data":   fmt.Sprintf("instance-id: %s\nlocal-hostname: %s\n", name, name),
		"/user-data":   fmt.Sprintf(userData, l.pubKey),
		"/vendor-data": "",
	}
	vm.seed = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, body)
	})}
	go vm.seed.Serve(seed) //nolint:errcheck // Serve returns when Stop closes the server
	port, err := freePort()
	if err != nil {
		return nil, err
	}
	args, err := qemuArgs(l.Arch, disk, port, seed.Addr().(*net.TCPAddr).Port, vm.dir)
	if err != nil {
		return nil, err
	}
	qemuLog, err := os.Create(filepath.Join(vm.dir, "qemu.log"))
	if err != nil {
		return nil, err
	}
	defer qemuLog.Close()
	vm.cmd = exec.Command(args[0], args[1:]...)
	vm.cmd.Stdout, vm.cmd.Stderr = qemuLog, qemuLog
	if err := vm.cmd.Start(); err != nil {
		return nil, fmt.Errorf("start qemu: %w", err)
	}
	vm.exited = make(chan struct{})
	go func() {
		vm.cmd.Wait() //nolint:errcheck // Stop kills qemu; wait only notices the exit
		close(vm.exited)
	}()
	host := fmt.Sprintf("Host %s\n  HostName 127.0.0.1\n  Port %d\n", name, port)
	if err := os.WriteFile(filepath.Join(l.Dir, "hosts", name+".conf"), []byte(host), 0o644); err != nil {
		return nil, err
	}
	if err := vm.wait(ctx); err != nil {
		return nil, err
	}
	return vm, nil
}

func (vm *VM) wait(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	for {
		if _, err := vm.Run(ctx, "cloud-init status --wait >/dev/null"); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			log, _ := os.ReadFile(filepath.Join(vm.dir, "console.log"))
			return fmt.Errorf("vm %s did not start: %w\n%s", vm.Name, ctx.Err(), tail(string(log), 30))
		case <-vm.exited:
			log, _ := os.ReadFile(filepath.Join(vm.dir, "qemu.log"))
			return fmt.Errorf("qemu for vm %s exited: %s", vm.Name, log)
		case <-time.After(2 * time.Second):
		}
	}
}

func tail(s string, n int) string {
	lines := strings.Split(s, "\n")
	return strings.Join(lines[max(0, len(lines)-n):], "\n")
}

func qemuArgs(arch, disk string, sshPort, seedPort int, dir string) ([]string, error) {
	common := []string{
		"-smp", "2", "-m", "1024",
		"-drive", "if=virtio,format=qcow2,file=" + disk,
		"-netdev", fmt.Sprintf("user,id=net0,hostfwd=tcp:127.0.0.1:%d-:22", sshPort),
		"-device", "virtio-net-pci,netdev=net0",
		"-smbios", fmt.Sprintf("type=1,serial=ds=nocloud;s=http://10.0.2.2:%d/", seedPort),
		"-display", "none", "-monitor", "none",
		"-serial", "file:" + filepath.Join(dir, "console.log"),
	}
	switch arch {
	case "arm64":
		bin, err := exec.LookPath("qemu-system-aarch64")
		if err != nil {
			return nil, err
		}
		firmware := filepath.Join(filepath.Dir(bin), "..", "share", "qemu", "edk2-aarch64-code.fd")
		return append([]string{bin, "-machine", "virt", "-accel", "hvf", "-cpu", "host",
			"-drive", "if=pflash,format=raw,readonly=on,file=" + firmware}, common...), nil
	case "amd64":
		bin, err := exec.LookPath("qemu-system-x86_64")
		if err != nil {
			return nil, err
		}
		return append([]string{bin, "-machine", "q35", "-accel", "tcg", "-cpu", "max"}, common...), nil
	}
	return nil, fmt.Errorf("unknown architecture %q", arch)
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// Run runs a shell command as root on the VM over ssh.
func (vm *VM) Run(ctx context.Context, command string) (string, error) {
	command = "sudo sh -c " + quote(command)
	cmd := exec.CommandContext(ctx, filepath.Join(vm.lab.Dir, "bin", "ssh"), vm.Name, command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s: %w: %s", command, err, out)
	}
	return string(out), nil
}

// Stop ends the VM. Its files stay in the lab directory.
func (vm *VM) Stop() {
	if vm.exited != nil {
		vm.cmd.Process.Kill() //nolint:errcheck // the VM may have exited
		<-vm.exited
	}
	if vm.seed != nil {
		vm.seed.Close()
	}
	os.Remove(filepath.Join(vm.lab.Dir, "hosts", vm.Name+".conf"))
}

func quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// FromEnv returns the image and architecture from WINCH_VM_IMAGE and
// WINCH_VM_ARCH.
func FromEnv() (image, arch string, err error) {
	image, arch = os.Getenv("WINCH_VM_IMAGE"), os.Getenv("WINCH_VM_ARCH")
	if image == "" || arch == "" {
		return "", "", errors.New("WINCH_VM_IMAGE is not set; run make test-integration")
	}
	return image, arch, nil
}
