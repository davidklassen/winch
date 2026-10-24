// vmrun starts one VM named "demo" for a demo by hand and keeps it running
// until Ctrl-C.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/davidklassen/winch/internal/vmtest"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "vmrun:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	image, arch, err := vmtest.FromEnv()
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "winch-vm-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	lab, err := vmtest.NewLab(ctx, dir, image, arch)
	if err != nil {
		return err
	}
	fmt.Println("starting the VM demo ...")
	vm, err := lab.Start(ctx, "demo")
	if err != nil {
		return err
	}
	defer vm.Stop()
	fmt.Printf("VM demo is ready. In another terminal:\n  export PATH=%s/bin:$PATH\n  ssh demo\nCtrl-C stops it.\n", dir)
	<-ctx.Done()
	return nil
}
