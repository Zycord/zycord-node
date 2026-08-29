//go:build darwin

package main

// Wails v2.15.0 calls -[UTType typeWithFilenameExtension:] for the file
// dialog's filters (internal/frontend/desktop/darwin/WailsContext.m) but does
// not name UniformTypeIdentifiers in its own cgo LDFLAGS, so the link fails
// with an undefined _OBJC_CLASS_$_UTType on macOS. Naming the framework here
// is the smallest fix that does not fork the dependency; delete this file when
// a Wails release links it itself.

/*
#cgo LDFLAGS: -framework UniformTypeIdentifiers
*/
import "C"
