package localnode

import (
	"os"
	"syscall"
)

// createNoWindow keeps the node's console from appearing beside a GUI
// application. The wallet is a windows-subsystem binary precisely so that no
// terminal opens with it (desktop/README.md); its child must not undo that.
const createNoWindow = 0x08000000

func sysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
}

// Windows has no SIGTERM to send another process. Kill is what there is; the
// node's store is repaired on the next start rather than lost.
func terminate(p *os.Process) error { return p.Kill() }
