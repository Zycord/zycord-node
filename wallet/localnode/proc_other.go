//go:build !linux && !windows

package localnode

import (
	"os"
	"syscall"
)

func sysProcAttr() *syscall.SysProcAttr { return nil }

func terminate(p *os.Process) error { return p.Signal(syscall.SIGTERM) }
