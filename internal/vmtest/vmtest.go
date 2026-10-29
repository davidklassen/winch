// Package vmtest starts Debian and Ubuntu VMs in QEMU for integration tests.
// A Lab holds the test SSH key and an ssh wrapper that reads the lab's SSH
// config, so winch and the tests reach each VM by its name. Each VM starts from a
// snapshot of a booted VM, and apt reads a local repository; both are kept in
// the cache directory.
package vmtest

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/davidklassen/winch/internal/session"
)

type Config struct {
	// OS names the image's release, such as debian-13 or ubuntu-24.04.
	OS    string
	Image string
	Arch  string
	// Cache holds the snapshot and the repository.
	Cache string
	// Repo is the directory with the package lists debian.list and
	// signed.list, and the test package definitions in packages/ and
	// signed/.
	Repo string
	// Online gives the VMs the internet and the apt sources of the image.
	Online bool
	// Refresh builds the repository again.
	Refresh bool
}

// FromEnv returns the configuration in WINCH_VM_OS, WINCH_VM_IMAGE,
// WINCH_VM_ARCH, WINCH_VM_CACHE, and WINCH_VM_ONLINE. repo is the directory
// of the test repository.
func FromEnv(repo string) (Config, error) {
	cfg := Config{
		OS:     os.Getenv("WINCH_VM_OS"),
		Image:  os.Getenv("WINCH_VM_IMAGE"),
		Arch:   os.Getenv("WINCH_VM_ARCH"),
		Cache:  os.Getenv("WINCH_VM_CACHE"),
		Online: os.Getenv("WINCH_VM_ONLINE") == "1",
	}
	if v := os.Getenv("WINCH_VM_ONLINE"); v != "" && v != "1" {
		return Config{}, fmt.Errorf("ONLINE=%s: use ONLINE=1 or no ONLINE", v)
	}
	if cfg.OS == "" || cfg.Image == "" || cfg.Arch == "" || cfg.Cache == "" {
		return Config{}, errors.New("WINCH_VM_OS, WINCH_VM_IMAGE, WINCH_VM_ARCH, or WINCH_VM_CACHE is not set; run make test-integration")
	}
	abs, err := filepath.Abs(repo)
	if err != nil {
		return Config{}, err
	}
	cfg.Repo = abs
	return cfg, nil
}

type Lab struct {
	Dir  string
	Arch string
	// PATH has the ssh wrapper first.
	PATH     string
	cfg      Config
	list     string
	snapshot string
	http     *http.Server
	httpPort int
}

// The guest reaches the lab's HTTP server at this address.
const labAddr = "10.0.2.100"

// NewLab prepares dir: the SSH config, the ssh wrapper, the HTTP server for
// the repository, the snapshot, and the repository. It builds the snapshot
// and the repository when the cache has none for their inputs.
func NewLab(ctx context.Context, dir string, cfg Config) (_ *Lab, err error) {
	if _, err := os.Stat(cfg.Image); err != nil {
		return nil, fmt.Errorf("vm image: %w (run make vm-image)", err)
	}
	for _, d := range []string{"bin", "hosts", "vms", "www/seed"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			return nil, err
		}
	}
	config := fmt.Sprintf(`Include %[1]s/hosts/*.conf
Host *
  User admin
  IdentityFile %[1]s/key
  IdentitiesOnly yes
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  LogLevel ERROR
`, dir)
	if err := os.WriteFile(filepath.Join(dir, "ssh_config"), []byte(config), 0o644); err != nil {
		return nil, err
	}
	wrapper := fmt.Sprintf("#!/bin/sh\nexec /usr/bin/ssh -F %s/ssh_config \"$@\"\n", dir)
	if err := os.WriteFile(filepath.Join(dir, "bin", "ssh"), []byte(wrapper), 0o755); err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	l := &Lab{
		Dir:  dir,
		Arch: cfg.Arch,
		PATH: filepath.Join(dir, "bin") + ":" + os.Getenv("PATH"),
		cfg:  cfg,
		list: filepath.Join(cfg.Repo, "debian.list"),
		// Each guest connection holds an nc process until the server
		// closes it.
		http:     &http.Server{Handler: http.FileServer(http.Dir(filepath.Join(dir, "www"))), IdleTimeout: 10 * time.Second},
		httpPort: ln.Addr().(*net.TCPAddr).Port,
	}
	go l.http.Serve(ln) //nolint:errcheck // Serve returns when Close closes the server
	defer func() {
		if err != nil {
			l.Close()
		}
	}()
	if err := l.ensureSnapshot(ctx); err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}
	if err := l.ensureRepo(ctx); err != nil {
		return nil, fmt.Errorf("repository: %w", err)
	}
	return l, nil
}

// Close stops the lab's HTTP server.
func (l *Lab) Close() {
	l.http.Close()
}

// Online reports whether the VMs have the internet and the image's sources.
func (l *Lab) Online() bool {
	return l.cfg.Online
}

// OS returns the release of the VMs, such as debian-13.
func (l *Lab) OS() string {
	return l.cfg.OS
}

// platform names the snapshot and the repository in the cache.
func (l *Lab) platform() string {
	return l.cfg.OS + "-" + l.Arch
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

// WriteHost writes the SSH config file of a host through a rename, so a
// parallel ssh never reads half of it, and returns its path.
func (l *Lab) WriteHost(name, conf string) (string, error) {
	path := filepath.Join(l.Dir, "hosts", name+".conf")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(conf), 0o644); err != nil {
		return "", err
	}
	return path, os.Rename(tmp, path)
}

// hint names the list when apt fails offline on a package that the local
// repository does not have.
func (l *Lab) hint(out string) string {
	if l.cfg.Online || !strings.Contains(out, "Unable to locate package") && !strings.Contains(out, "has no installation candidate") {
		return ""
	}
	return fmt.Sprintf("\nThe local apt repository does not have the package. Add it to %s; the next test run builds the repository again.", l.list)
}

type VM struct {
	Name   string
	lab    *Lab
	dir    string
	qmp    *qmp
	cmd    *exec.Cmd
	exited chan struct{}
	watch  *watchdog
}

// Start starts a VM from the snapshot and gives it the apt sources of the
// lab's mode.
func (l *Lab) Start(ctx context.Context, name string) (*VM, error) {
	vm, err := l.clone(ctx, name, l.cfg.Online)
	if err != nil {
		return nil, err
	}
	test := fmt.Sprintf("Types: deb\nURIs: http://%s/test/\nSuites: ./\nTrusted: yes\n", labAddr)
	sources := "printf '" + test + "' > /etc/apt/sources.list.d/winch-test.sources"
	if !l.cfg.Online {
		debian := strings.ReplaceAll(test, "/test/", "/debian/")
		sources = "rm /etc/apt/sources.list.d/*.sources && printf '" + debian + "' > /etc/apt/sources.list.d/winch-debian.sources && " + sources
	}
	if _, err := vm.Run(ctx, sources); err != nil {
		vm.Stop()
		return nil, err
	}
	return vm, nil
}

// clone starts a VM from the snapshot on its own disk layer, and sets the
// VM's clock over SSH as soon as SSH works.
func (l *Lab) clone(ctx context.Context, name string, online bool) (_ *VM, err error) {
	snap := filepath.Join(l.cfg.Cache, l.snapshot)
	vm, err := l.boot(ctx, name, filepath.Join(l.Dir, "vms", name), filepath.Join(snap, "disk.qcow2"), online, filepath.Join(snap, "state"))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			vm.Stop()
		}
	}()
	if err := vm.waitRunning(ctx); err != nil {
		return nil, err
	}
	// QEMU writes QMP events to stdout. A full pipe can block QEMU.
	go io.Copy(io.Discard, vm.qmp.r) //nolint:errcheck // the copy ends when QEMU exits
	wait, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	for {
		if err = vm.setClock(wait); err == nil {
			return vm, nil
		}
		select {
		case <-wait.Done():
			return nil, fmt.Errorf("vm %s does not answer: %w", name, err)
		case <-vm.exited:
			log, _ := os.ReadFile(filepath.Join(vm.dir, "qemu.log"))
			return nil, fmt.Errorf("qemu for vm %s exited: %s", name, log)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// setClock sets the VM's clock to the Mac's time. The VM asks for the time
// once the SSH session runs, so the setup of the session does not delay it.
func (vm *VM) setClock(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, filepath.Join(vm.lab.Dir, "bin", "ssh"), "-o", "ConnectTimeout=5", vm.Name,
		"sudo sh -c "+Quote(`echo ready; read t; date -u -s "@$t" >/dev/null`))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	if _, err := bufio.NewReader(stdout).ReadString('\n'); err == nil {
		now := time.Now()
		fmt.Fprintf(stdin, "%d.%09d\n", now.Unix(), now.Nanosecond())
	}
	stdin.Close()
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("set the clock: %w: %s", err, stderr.String())
	}
	return nil
}

// boot starts QEMU on a new disk layer over backing, with its files in dir.
// With state, the VM loads that saved machine; without, it boots.
func (l *Lab) boot(ctx context.Context, name, dir, backing string, online bool, state string) (_ *VM, err error) {
	vm := &VM{Name: name, lab: l, dir: dir}
	defer func() {
		if err != nil {
			vm.Stop()
		}
	}()
	if err := os.MkdirAll(vm.dir, 0o755); err != nil {
		return nil, err
	}
	disk := filepath.Join(vm.dir, "disk.qcow2")
	if out, err := exec.CommandContext(ctx, "qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", backing, disk, diskSize).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("qemu-img: %v: %s", err, out)
	}
	args, err := qemuArgs(l.Arch, disk, vm.dir, l.httpPort, online)
	if err != nil {
		return nil, err
	}
	if state != "" {
		args = append(args, "-incoming", "file:"+state)
	}
	logPath := filepath.Join(vm.dir, "qemu.log")
	qemuLog, err := os.Create(logPath)
	if err != nil {
		return nil, err
	}
	defer qemuLog.Close()
	vm.cmd = exec.Command(args[0], args[1:]...)
	vm.cmd.Stderr = qemuLog
	stdin, err := vm.cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := vm.cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := vm.cmd.Start(); err != nil {
		return nil, fmt.Errorf("start qemu: %w", err)
	}
	vm.exited = make(chan struct{})
	go func() {
		vm.cmd.Wait() //nolint:errcheck // Stop kills qemu; wait only notices the exit
		close(vm.exited)
	}()
	if vm.watch, err = startWatchdog(vm.cmd.Process.Pid); err != nil {
		return nil, err
	}
	vm.qmp = &qmp{w: stdin, r: bufio.NewReader(stdout)}
	if _, err := vm.qmp.r.ReadString('\n'); err != nil {
		// QEMU closes stdout when it exits.
		<-vm.exited
		log, _ := os.ReadFile(logPath)
		return nil, fmt.Errorf("vm %s: qmp greeting: %w: %s", name, err, log)
	}
	if err := vm.qmp.call("qmp_capabilities", nil, nil); err != nil {
		return nil, fmt.Errorf("vm %s: %w", name, err)
	}
	sshPort, err := vm.qmp.sshPort()
	if err != nil {
		return nil, fmt.Errorf("vm %s: %w", name, err)
	}
	if _, err := l.WriteHost(name, fmt.Sprintf("Host %s\n  HostName 127.0.0.1\n  Port %d\n", name, sshPort)); err != nil {
		return nil, err
	}
	return vm, nil
}

// waitRunning waits until QEMU has loaded the saved machine, then starts it.
func (vm *VM) waitRunning(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	for {
		var st struct{ Status string }
		if err := vm.qmp.call("query-status", nil, &st); err != nil {
			return fmt.Errorf("vm %s: %w", vm.Name, err)
		}
		// The snapshot holds a stopped machine.
		if st.Status == "paused" {
			if err := vm.qmp.call("cont", nil, nil); err != nil {
				return fmt.Errorf("vm %s: %w", vm.Name, err)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("vm %s did not load its snapshot: %w (status %s)", vm.Name, ctx.Err(), st.Status)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// waitBoot waits until cloud-init is done. ssh exits 255 while the VM boots;
// any other exit status is the result of cloud-init.
func (vm *VM) waitBoot(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	for {
		_, err := vm.Run(ctx, "cloud-init status --wait --long")
		if err == nil {
			return nil
		}
		if exit, ok := errors.AsType[*exec.ExitError](err); ok && ctx.Err() == nil && exit.ExitCode() != 255 {
			return fmt.Errorf("vm %s: cloud-init failed: %w", vm.Name, err)
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

// diskSize is the size of each VM's disk. cloud-init grows the root file
// system to it. Ubuntu 26.04's image has too little free space for the test
// repository.
const diskSize = "8G"

// qemuArgs returns the QEMU command of a VM. The SSH forward binds port 0,
// so the kernel picks a free port. Offline, restrict=on cuts the VM off from
// every address but the guestfwd to the lab's HTTP server.
func qemuArgs(arch, disk, dir string, httpPort int, online bool) ([]string, error) {
	netdev := fmt.Sprintf("user,id=net0,hostfwd=tcp:127.0.0.1:0-:22,guestfwd=tcp:%s:80-cmd:nc 127.0.0.1 %d", labAddr, httpPort)
	if !online {
		netdev += ",restrict=on"
	}
	common := []string{
		"-smp", "2", "-m", "1024",
		"-drive", "if=virtio,format=qcow2,file=" + disk,
		"-netdev", netdev,
		"-device", "virtio-net-pci,netdev=net0",
		"-smbios", "type=1,serial=ds=nocloud;s=http://" + labAddr + "/seed/",
		"-display", "none", "-monitor", "none",
		"-serial", "file:" + filepath.Join(dir, "console.log"),
		"-qmp", "stdio",
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
		accel, cpu := "tcg", "max"
		if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
			accel, cpu = "kvm", "host"
		}
		return append([]string{bin, "-machine", "q35", "-accel", accel, "-cpu", cpu}, common...), nil
	}
	return nil, fmt.Errorf("unknown architecture %q", arch)
}

// Run runs a shell command as root on the VM over ssh. A login while sshd
// executes itself again after a reload gets a reset before the handshake; Run
// then logs in once more after two seconds, as winch does.
func (vm *VM) Run(ctx context.Context, command string) (string, error) {
	command = "sudo sh -c " + Quote(command)
	ssh := func() ([]byte, error) {
		return exec.CommandContext(ctx, filepath.Join(vm.lab.Dir, "bin", "ssh"), "-o", "ConnectTimeout=5", vm.Name, command).CombinedOutput()
	}
	out, err := ssh()
	if exit, ok := errors.AsType[*exec.ExitError](err); ok && session.Dropped(exit.ExitCode(), string(out)) {
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
			out, err = ssh()
		}
	}
	if err != nil {
		return string(out), fmt.Errorf("%s: %w: %s%s", command, err, out, vm.lab.hint(string(out)))
	}
	return string(out), nil
}

// stream runs a shell command as root on the VM with stdin and stdout.
func (vm *VM) stream(ctx context.Context, command string, stdin io.Reader, stdout io.Writer) error {
	cmd := exec.CommandContext(ctx, filepath.Join(vm.lab.Dir, "bin", "ssh"), "-o", "ConnectTimeout=5", vm.Name, "sudo sh -c "+Quote(command))
	var stderr strings.Builder
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w: %s", command, err, stderr.String())
	}
	return nil
}

// Freeze stops the VM process with SIGSTOP. The VM does not answer, and its
// connections stay open.
func (vm *VM) Freeze() error {
	return vm.cmd.Process.Signal(syscall.SIGSTOP)
}

func (vm *VM) Thaw() error {
	return vm.cmd.Process.Signal(syscall.SIGCONT)
}

// Stop ends the VM. Its files stay in the lab directory.
func (vm *VM) Stop() {
	if vm.watch != nil {
		vm.watch.stop()
	}
	if vm.exited != nil {
		vm.cmd.Process.Kill() //nolint:errcheck // the VM may have exited
		<-vm.exited
	}
	os.Remove(filepath.Join(vm.lab.Dir, "hosts", vm.Name+".conf"))
}

func Quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// watchdog kills a process when the test process ends without stop, for
// example at the time limit of go test. It reads a pipe whose only write end
// the test process holds; the kernel closes it when the test process ends.
type watchdog struct {
	cmd *exec.Cmd
	w   *os.File
}

func startWatchdog(pid int) (*watchdog, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	cmd := exec.Command("sh", "-c", `read _ || kill -9 "$1"`, "sh", strconv.Itoa(pid))
	cmd.Stdin = r
	if err := cmd.Start(); err != nil {
		w.Close()
		return nil, fmt.Errorf("start watchdog: %w", err)
	}
	return &watchdog{cmd: cmd, w: w}, nil
}

// stop ends the watchdog and leaves the process running.
func (d *watchdog) stop() {
	d.w.Write([]byte("\n")) //nolint:errcheck // Stop kills the process next
	d.w.Close()
	d.cmd.Wait() //nolint:errcheck // the watchdog exits 0
}
