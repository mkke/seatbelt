// cgo_helper is a test binary that applies a seatbelt sandbox via the cgo
// package (sandbox_init) and then runs test functions.
//
// Usage: cgo_helper <profile-spec> <test-name> [args...]
//
// Profile specs:
//
//	minimal         — Minimal preset only
//	readonly:/path  — Minimal + ReadOnly for the given path
//	readwrite:/path — Minimal + ReadWrite for the given path
//	network         — Minimal + AllowNetwork + ReadOnly for DNS paths
//	double          — Apply twice (to test double-apply error)
//	invalid         — Invalid SBPL to test error handling
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/mkke/seatbelt"
	sbcgo "github.com/mkke/seatbelt/cgo"
)

type result struct {
	OK   bool   `json:"ok"`
	Err  string `json:"err,omitempty"`
	Data string `json:"data,omitempty"`
}

func report(ok bool, err error, data ...string) {
	r := result{OK: ok}
	if err != nil {
		r.Err = err.Error()
	}
	if len(data) > 0 {
		r.Data = data[0]
	}
	json.NewEncoder(os.Stdout).Encode(r)
}

func succeed(data ...string) {
	d := ""
	if len(data) > 0 {
		d = data[0]
	}
	report(true, nil, d)
}

func fail(err error) {
	report(false, err)
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: cgo_helper <profile-spec> <test-name> [args...]\n")
		os.Exit(2)
	}

	profileSpec := os.Args[1]
	testName := os.Args[2]
	args := os.Args[3:]

	// Apply the sandbox based on the profile spec.
	if err := applySandbox(profileSpec); err != nil {
		fail(err)
		os.Exit(1)
	}

	// Run the test function.
	runTest(testName, args)
}

func applySandbox(spec string) error {
	switch {
	case spec == "minimal":
		return sbcgo.Apply(
			seatbelt.ReadOnly("/usr/lib", "/usr/share", "/System/Library"),
		)

	case strings.HasPrefix(spec, "readonly:"):
		path := strings.TrimPrefix(spec, "readonly:")
		return sbcgo.Apply(
			seatbelt.ReadOnly("/usr/lib", "/usr/share", "/System/Library"),
			seatbelt.ReadOnly(path),
		)

	case strings.HasPrefix(spec, "readwrite:"):
		path := strings.TrimPrefix(spec, "readwrite:")
		return sbcgo.Apply(
			seatbelt.ReadOnly("/usr/lib", "/usr/share", "/System/Library"),
			seatbelt.ReadWrite(path),
		)

	case spec == "network":
		return sbcgo.Apply(
			seatbelt.ReadOnly("/usr/lib", "/usr/share", "/System/Library"),
			seatbelt.ReadOnly("/etc", "/private/var/run"),
			seatbelt.AllowNetwork(),
		)

	case spec == "double":
		err := sbcgo.Apply(
			seatbelt.ReadOnly("/usr/lib", "/usr/share", "/System/Library"),
		)
		if err != nil {
			return err
		}
		// Second apply should return ErrAlreadySandboxed.
		err2 := sbcgo.Apply(seatbelt.ReadOnly("/tmp"))
		if err2 != nil {
			// Store the error message as "data" for the test to check.
			succeed(err2.Error())
			os.Exit(0)
		}
		return fmt.Errorf("expected error on double apply, got nil")

	case spec == "invalid":
		return sbcgo.Apply(
			seatbelt.WithoutMinimal(),
			seatbelt.Custom("(this is not valid sbpl 🤯)"),
		)

	default:
		return fmt.Errorf("unknown profile spec: %s", spec)
	}
}

func runTest(name string, args []string) {
	tests := map[string]func([]string){
		"noop": func(args []string) {
			succeed()
		},

		"fs-read-file": func(args []string) {
			data, err := os.ReadFile(args[0])
			if err != nil {
				fail(err)
				return
			}
			succeed(fmt.Sprintf("%d bytes", len(data)))
		},

		"fs-write-file": func(args []string) {
			err := os.WriteFile(args[0], []byte("seatbelt-test"), 0644)
			if err != nil {
				fail(err)
				return
			}
			succeed()
		},

		"fs-stat": func(args []string) {
			info, err := os.Stat(args[0])
			if err != nil {
				fail(err)
				return
			}
			succeed(info.Name())
		},

		"net-dial-tcp": func(args []string) {
			addr := "1.1.1.1:80"
			if len(args) > 0 {
				addr = args[0]
			}
			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				fail(err)
				return
			}
			conn.Close()
			succeed()
		},

		"net-listen-tcp": func(args []string) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				fail(err)
				return
			}
			ln.Close()
			succeed()
		},

		"net-http-get": func(args []string) {
			url := "http://example.com"
			if len(args) > 0 {
				url = args[0]
			}
			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Get(url)
			if err != nil {
				fail(err)
				return
			}
			resp.Body.Close()
			succeed(fmt.Sprintf("status %d", resp.StatusCode))
		},

		"proc-exec": func(args []string) {
			cmd := exec.Command(args[0], args[1:]...)
			out, err := cmd.CombinedOutput()
			if err != nil {
				fail(fmt.Errorf("%w: %s", err, string(out)))
				return
			}
			succeed(strings.TrimSpace(string(out)))
		},

		"sysctl-read": func(args []string) {
			name := "kern.ostype"
			if len(args) > 0 {
				name = args[0]
			}
			val, err := syscall.Sysctl(name)
			if err != nil {
				fail(err)
				return
			}
			succeed(val)
		},

		"signal-self": func(args []string) {
			err := syscall.Kill(os.Getpid(), 0)
			if err != nil {
				fail(err)
				return
			}
			succeed()
		},

		"escape-chroot": func(args []string) {
			err := syscall.Chroot("/tmp")
			if err != nil {
				fail(err)
				return
			}
			succeed()
		},

		"escape-ptrace": func(args []string) {
			const ptAttach = 10
			_, _, errno := syscall.Syscall(syscall.SYS_PTRACE,
				uintptr(ptAttach), uintptr(1), 0)
			if errno != 0 {
				fail(errno)
				return
			}
			succeed()
		},

		"escape-symlink-pivot": func(args []string) {
			writableDir := args[0]
			targetPath := args[1]
			linkPath := filepath.Join(writableDir, "escape-link")
			if err := os.Symlink(targetPath, linkPath); err != nil {
				fail(fmt.Errorf("create symlink: %w", err))
				return
			}
			defer os.Remove(linkPath)
			data, err := os.ReadFile(linkPath)
			if err != nil {
				fail(fmt.Errorf("read via symlink: %w", err))
				return
			}
			succeed(fmt.Sprintf("read %d bytes", len(data)))
		},

		"escape-ipc-shm": func(args []string) {
			name := "/seatbelt-test-shm"
			nameBytes := append([]byte(name), 0)
			fd, _, errno := syscall.Syscall(
				syscall.SYS_SHM_OPEN,
				uintptr(unsafe.Pointer(&nameBytes[0])),
				uintptr(os.O_RDWR|os.O_CREATE),
				0600,
			)
			if errno != 0 {
				fail(errno)
				return
			}
			syscall.Close(int(fd))
			succeed()
		},

		"cgo-is-applied": func(args []string) {
			succeed(fmt.Sprintf("%v", sbcgo.IsApplied()))
		},

		"concurrent-read": func(args []string) {
			path := args[0]
			var wg sync.WaitGroup
			errCh := make(chan error, 100)
			for i := 0; i < 100; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, err := os.ReadFile(path)
					if err != nil {
						errCh <- err
					}
				}()
			}
			wg.Wait()
			close(errCh)
			var errs []string
			for err := range errCh {
				errs = append(errs, err.Error())
			}
			if len(errs) > 0 {
				fail(fmt.Errorf("%d errors: %s", len(errs), strings.Join(errs, "; ")))
				return
			}
			succeed("100 concurrent reads")
		},

		"print-runtime": func(args []string) {
			succeed(fmt.Sprintf("os=%s arch=%s", runtime.GOOS, runtime.GOARCH))
		},
	}

	fn, ok := tests[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown test: %s\n", name)
		os.Exit(2)
	}
	fn(args)
}
