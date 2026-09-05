package localnode

import (
	"os"
	"syscall"
)

// sysProcAttr asks the kernel to send the node SIGTERM if the wallet dies
// without stopping it. A wallet that crashes must not leave a node running
// that nothing will ever stop.
func sysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
}

func terminate(p *os.Process) error { return p.Signal(syscall.SIGTERM) }
