// Package seatbelt provides declarative macOS sandbox (Seatbelt) enforcement
// for Go processes.
//
// It offers a composable, allow-list API inspired by go-landlock and a
// re-execution model inspired by go-daemon, tailored to the capabilities
// of the macOS Seatbelt subsystem.
//
// # Basic Usage
//
// The primary API is [Restrict], which re-executes the current process
// under a sandbox with the given rules:
//
//	child, err := seatbelt.Restrict(
//	    seatbelt.ReadOnly("/usr", "/bin"),
//	    seatbelt.ReadWrite(workDir),
//	    seatbelt.AllowExec("/usr/bin/git"),
//	    seatbelt.DenyNetwork(),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if child != nil {
//	    // Parent: wait for sandboxed child.
//	    state, _ := child.Wait()
//	    os.Exit(state.ExitCode())
//	}
//	defer seatbelt.Release()
//	// Sandboxed code runs here.
//
// # Combining with go-daemon
//
// The re-execution pattern composes with go-daemon's daemonization.
// Daemonize first, then sandbox:
//
//	// Stage 1: Daemonize
//	child, err := daemonCtx.Reborn()
//	if child != nil {
//	    return
//	}
//	defer daemonCtx.Release()
//
//	// Stage 2: Sandbox
//	child, err = seatbelt.Restrict(
//	    seatbelt.ReadOnly("/usr", "/etc"),
//	    seatbelt.ReadWrite("/var/lib/myapp"),
//	    seatbelt.DenyNetwork(),
//	)
//	if child != nil {
//	    state, _ := child.Wait()
//	    os.Exit(state.ExitCode())
//	}
//	defer seatbelt.Release()
//	// Running as daemon + sandboxed.
//
// # Self-Sandboxing (cgo)
//
// For in-place sandboxing without re-execution, use the seatbelt/cgo
// sub-package which calls sandbox_init directly:
//
//	import sbcgo "github.com/mkke/seatbelt/cgo"
//
//	err := sbcgo.Apply(
//	    seatbelt.ReadOnly("/usr"),
//	    seatbelt.ReadWrite(workDir),
//	    seatbelt.DenyNetwork(),
//	)
package seatbelt
