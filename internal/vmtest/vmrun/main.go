// vmrun starts the VMs demo, demo2, ... for a demo by hand and keeps them
// running until Ctrl-C. With -refresh, it builds the test apt repository
// again and exits.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
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
	refresh := flag.Bool("refresh", false, "build the test apt repository again and exit")
	n := flag.Int("n", 1, "the number of VMs")
	flag.Parse()
	if *n < 1 {
		return fmt.Errorf("-n %d: start at least one VM", *n)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cfg, err := vmtest.FromEnv("test/repo")
	if err != nil {
		return err
	}
	cfg.Refresh = *refresh
	dir, err := os.MkdirTemp("", "winch-vm-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	lab, err := vmtest.NewLab(ctx, dir, cfg)
	if err != nil {
		return err
	}
	defer lab.Close()
	if *refresh {
		return nil
	}
	var names []string
	for i := range *n {
		name := "demo"
		if i > 0 {
			name += strconv.Itoa(i + 1)
		}
		fmt.Printf("starting the VM %s ...\n", name)
		vm, err := lab.Start(ctx, name)
		if err != nil {
			return err
		}
		defer vm.Stop()
		names = append(names, name)
	}
	fmt.Printf("VMs %s are ready. In another terminal:\n  export PATH=%s/bin:$PATH\n  ssh %s\nCtrl-C stops them.\n", strings.Join(names, ", "), dir, names[0])
	<-ctx.Done()
	return nil
}
