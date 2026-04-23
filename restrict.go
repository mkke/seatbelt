package seatbelt

import (
	"errors"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

const (
	envMarker      = "_SEATBELT_CHILD"
	envProfile     = "_SEATBELT_PROFILE"
	envProfileFile = "_SEATBELT_PROFILE_FILE"
	markerVal      = "1"
)

// IsSandboxed reports whether the current process was re-executed
// inside a seatbelt sandbox by Restrict.
func IsSandboxed() bool {
	return os.Getenv(envMarker) == markerVal
}

// SandboxProfile returns the SBPL profile source if running inside
// a seatbelt sandbox, or an empty string otherwise.
func SandboxProfile() string {
	return os.Getenv(envProfile)
}

// Restrict re-executes the current process under a seatbelt sandbox
// with the given rules.
//
// In the parent process, it returns the child *os.Process (non-nil).
// The caller should wait on the child and propagate its exit code.
//
// In the sandboxed child process, it returns (nil, nil).
// The caller should proceed with application logic and defer Release().
//
// If the process is already sandboxed, it returns ErrAlreadySandboxed.
func Restrict(rules ...Rule) (*os.Process, error) {
	if runtime.GOOS != "darwin" {
		return nil, ErrUnsupportedPlatform
	}

	// Child path: already sandboxed, just return.
	if IsSandboxed() {
		return nil, nil
	}

	sbExec, err := findSandboxExec()
	if err != nil {
		return nil, err
	}

	profile, err := BuildProfile(rules...)
	if err != nil {
		return nil, err
	}

	self, err := os.Executable()
	if err != nil {
		return nil, err
	}

	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	sbplSource := profile.String()

	// Build child environment: copy current env, add markers.
	env := os.Environ()
	env = append(env, envMarker+"="+markerVal)
	env = append(env, envProfile+"="+sbplSource)

	// Decide whether to pass profile via -p (arg) or -f (temp file).
	// ARG_MAX on macOS is 1MB, but we use a conservative 128KB threshold.
	const argThreshold = 128 * 1024
	var args []string
	var profileFile string

	if len(sbplSource) > argThreshold {
		// Write profile to a temp file.
		f, err := os.CreateTemp("", "seatbelt-profile-*.sb")
		if err != nil {
			return nil, err
		}
		if _, err := f.WriteString(sbplSource); err != nil {
			f.Close()
			os.Remove(f.Name())
			return nil, err
		}
		f.Close()
		profileFile = f.Name()
		env = append(env, envProfileFile+"="+profileFile)
		args = append(args, sbExec, "-f", profileFile, self)
	} else {
		args = append(args, sbExec, "-p", sbplSource, self)
	}

	// Append original arguments (skip argv[0]).
	args = append(args, os.Args[1:]...)

	attr := &os.ProcAttr{
		Dir:   cwd,
		Env:   env,
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
		Sys:   &syscall.SysProcAttr{},
	}

	child, err := os.StartProcess(sbExec, args, attr)
	if err != nil {
		if profileFile != "" {
			os.Remove(profileFile)
		}
		return nil, err
	}

	// Forward signals to the child process.
	go forwardSignals(child)

	return child, nil
}

// Release cleans up resources after a sandboxed process exits.
// It removes any temporary profile file created during Restrict.
func Release() {
	if f := os.Getenv(envProfileFile); f != "" {
		os.Remove(f)
	}
}

// forwardSignals forwards SIGINT, SIGTERM, and SIGHUP to the child process.
// It exits once child.Signal reports os.ErrProcessDone, which happens after
// the parent has waited on the child.
func forwardSignals(child *os.Process) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case sig := <-sigCh:
			if err := child.Signal(sig); errors.Is(err, os.ErrProcessDone) {
				return
			}
		case <-ticker.C:
			if err := child.Signal(syscall.Signal(0)); errors.Is(err, os.ErrProcessDone) {
				return
			}
		}
	}
}

// findSandboxExec locates the sandbox-exec binary.
func findSandboxExec() (string, error) {
	// Standard location.
	if info, err := os.Stat("/usr/bin/sandbox-exec"); err == nil && !info.IsDir() {
		return "/usr/bin/sandbox-exec", nil
	}
	return "", ErrSandboxExecNotFound
}
