// sandbox_helper is a test binary that runs specific test functions inside
// a seatbelt sandbox. It is compiled and executed by the test suite via
// sandbox-exec.
//
// Usage: sandbox_helper <test-name> [args...]
//
// Each test function attempts an operation and prints a JSON result:
//
//	{"ok": true}              — operation succeeded
//	{"ok": false, "err": "…"} — operation failed with the given error
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
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: sandbox_helper <test-name> [args...]\n")
		os.Exit(2)
	}

	testName := os.Args[1]
	args := os.Args[2:]

	tests := map[string]func([]string){
		// ── File system tests ──────────────────────────────────────

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

		"fs-mkdir": func(args []string) {
			err := os.Mkdir(args[0], 0755)
			if err != nil {
				fail(err)
				return
			}
			succeed()
		},

		"fs-remove": func(args []string) {
			err := os.Remove(args[0])
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

		"fs-rename": func(args []string) {
			err := os.Rename(args[0], args[1])
			if err != nil {
				fail(err)
				return
			}
			succeed()
		},

		"fs-symlink-read": func(args []string) {
			// args[0] = symlink path, should already exist
			data, err := os.ReadFile(args[0])
			if err != nil {
				fail(err)
				return
			}
			succeed(fmt.Sprintf("%d bytes", len(data)))
		},

		"fs-create-symlink": func(args []string) {
			// args[0] = target, args[1] = link path
			err := os.Symlink(args[0], args[1])
			if err != nil {
				fail(err)
				return
			}
			succeed()
		},

		"fs-hardlink": func(args []string) {
			// args[0] = source, args[1] = link path
			err := os.Link(args[0], args[1])
			if err != nil {
				fail(err)
				return
			}
			succeed()
		},

		"fs-glob": func(args []string) {
			matches, err := filepath.Glob(args[0])
			if err != nil {
				fail(err)
				return
			}
			succeed(fmt.Sprintf("%d matches", len(matches)))
		},

		"fs-readdir": func(args []string) {
			entries, err := os.ReadDir(args[0])
			if err != nil {
				fail(err)
				return
			}
			succeed(fmt.Sprintf("%d entries", len(entries)))
		},

		"fs-open-many": func(args []string) {
			dir := args[0]
			var files []*os.File
			for i := 0; i < 1000; i++ {
				f, err := os.CreateTemp(dir, "seatbelt-stress-*")
				if err != nil {
					fail(fmt.Errorf("failed at file %d: %w", i, err))
					return
				}
				files = append(files, f)
			}
			for _, f := range files {
				f.Close()
				os.Remove(f.Name())
			}
			succeed(fmt.Sprintf("opened %d files", len(files)))
		},

		"fs-large-file": func(args []string) {
			path := filepath.Join(args[0], "large-test-file")
			// Write 10MB
			data := make([]byte, 10*1024*1024)
			for i := range data {
				data[i] = byte(i % 256)
			}
			if err := os.WriteFile(path, data, 0644); err != nil {
				fail(err)
				return
			}
			read, err := os.ReadFile(path)
			if err != nil {
				fail(err)
				return
			}
			os.Remove(path)
			if len(read) != len(data) {
				fail(fmt.Errorf("size mismatch: wrote %d, read %d", len(data), len(read)))
				return
			}
			succeed(fmt.Sprintf("%d bytes", len(read)))
		},

		"fs-write-only-write": func(args []string) {
			f, err := os.OpenFile(args[0], os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
			if err != nil {
				fail(err)
				return
			}
			_, err = f.Write([]byte("write-only-test"))
			f.Close()
			if err != nil {
				fail(err)
				return
			}
			succeed()
		},

		"fs-write-only-read": func(args []string) {
			_, err := os.ReadFile(args[0])
			if err != nil {
				fail(err)
				return
			}
			succeed()
		},

		// ── Network tests ──────────────────────────────────────────

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
			addr := ln.Addr().String()
			ln.Close()
			succeed(addr)
		},

		"net-dial-udp": func(args []string) {
			addr := "8.8.8.8:53"
			if len(args) > 0 {
				addr = args[0]
			}
			conn, err := net.DialTimeout("udp", addr, 5*time.Second)
			if err != nil {
				fail(err)
				return
			}
			conn.Close()
			succeed()
		},

		"net-dial-unix": func(args []string) {
			conn, err := net.Dial("unix", args[0])
			if err != nil {
				fail(err)
				return
			}
			conn.Close()
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

		"net-dns-lookup": func(args []string) {
			host := "example.com"
			if len(args) > 0 {
				host = args[0]
			}
			addrs, err := net.LookupHost(host)
			if err != nil {
				fail(err)
				return
			}
			succeed(strings.Join(addrs, ","))
		},

		"net-localhost": func(args []string) {
			// Try to connect to localhost on a port
			port := "12345"
			if len(args) > 0 {
				port = args[0]
			}
			conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 2*time.Second)
			if err != nil {
				fail(err)
				return
			}
			conn.Close()
			succeed()
		},

		// ── Process execution tests ────────────────────────────────

		"proc-exec": func(args []string) {
			cmd := exec.Command(args[0], args[1:]...)
			out, err := cmd.CombinedOutput()
			if err != nil {
				fail(fmt.Errorf("%w: %s", err, string(out)))
				return
			}
			succeed(strings.TrimSpace(string(out)))
		},

		"proc-exec-shell-escape": func(args []string) {
			// Try to use a shell to execute a disallowed command
			cmd := exec.Command("/bin/sh", "-c", args[0])
			out, err := cmd.CombinedOutput()
			if err != nil {
				fail(fmt.Errorf("%w: %s", err, string(out)))
				return
			}
			succeed(strings.TrimSpace(string(out)))
		},

		"proc-fork-bomb": func(args []string) {
			// Attempt rapid forking (limited to 10 to not actually harm the system)
			for i := 0; i < 10; i++ {
				cmd := exec.Command(os.Args[0], "noop")
				if err := cmd.Start(); err != nil {
					fail(fmt.Errorf("fork %d failed: %w", i, err))
					return
				}
				cmd.Wait()
			}
			succeed("forked 10 times")
		},

		"proc-exec-written-script": func(args []string) {
			// Write a script to an allowed path, then try to execute it
			scriptPath := filepath.Join(args[0], "test-script.sh")
			err := os.WriteFile(scriptPath, []byte("#!/bin/sh\necho escaped"), 0755)
			if err != nil {
				fail(fmt.Errorf("write script: %w", err))
				return
			}
			cmd := exec.Command(scriptPath)
			out, err := cmd.CombinedOutput()
			if err != nil {
				fail(fmt.Errorf("exec script: %w: %s", err, string(out)))
				return
			}
			succeed(strings.TrimSpace(string(out)))
		},

		// ── Mach IPC tests ─────────────────────────────────────────

		"mach-tls-handshake": func(args []string) {
			// TLS handshake requires com.apple.trustd.agent Mach lookup
			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Get("https://example.com")
			if err != nil {
				fail(err)
				return
			}
			resp.Body.Close()
			succeed(fmt.Sprintf("status %d", resp.StatusCode))
		},

		// ── Sysctl tests ──────────────────────────────────────────

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

		// ── Signal tests ──────────────────────────────────────────

		"signal-self": func(args []string) {
			err := syscall.Kill(os.Getpid(), 0)
			if err != nil {
				fail(err)
				return
			}
			succeed()
		},

		"signal-other": func(args []string) {
			// Try to signal PID 1 (launchd) — should always be denied
			err := syscall.Kill(1, 0)
			if err != nil {
				fail(err)
				return
			}
			succeed()
		},

		// ── Escape vector tests ───────────────────────────────────

		"escape-symlink-pivot": func(args []string) {
			// Create symlink in writable dir pointing to restricted path, read via symlink
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
			succeed(fmt.Sprintf("read %d bytes via symlink", len(data)))
		},

		"escape-rename-to-denied": func(args []string) {
			// Write file to allowed path, try to rename to denied path
			srcPath := args[0]
			dstPath := args[1]
			if err := os.WriteFile(srcPath, []byte("escape-test"), 0644); err != nil {
				fail(fmt.Errorf("write: %w", err))
				return
			}
			defer os.Remove(srcPath)
			err := os.Rename(srcPath, dstPath)
			if err != nil {
				fail(fmt.Errorf("rename: %w", err))
				return
			}
			defer os.Remove(dstPath)
			succeed("renamed to denied path")
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
			// Attempt PT_ATTACH (26) to another process
			pid := 1 // launchd
			const ptAttach = 10
			_, _, errno := syscall.Syscall(syscall.SYS_PTRACE,
				uintptr(ptAttach),
				uintptr(pid), 0)
			if errno != 0 {
				fail(errno)
				return
			}
			succeed()
		},

		"escape-applescript": func(args []string) {
			cmd := exec.Command("osascript", "-e", `do shell script "echo escaped"`)
			out, err := cmd.CombinedOutput()
			if err != nil {
				fail(fmt.Errorf("%w: %s", err, string(out)))
				return
			}
			succeed(strings.TrimSpace(string(out)))
		},

		"escape-keychain": func(args []string) {
			// Try to access macOS Keychain via security command
			cmd := exec.Command("/usr/bin/security", "list-keychains")
			out, err := cmd.CombinedOutput()
			if err != nil {
				fail(fmt.Errorf("%w: %s", err, string(out)))
				return
			}
			succeed(strings.TrimSpace(string(out)))
		},

		"escape-double-sandbox-tighter": func(args []string) {
			// Already sandboxed, try to apply tighter sandbox via sandbox-exec
			cmd := exec.Command("/usr/bin/sandbox-exec", "-n", "pure-computation",
				os.Args[0], "sysctl-read")
			out, err := cmd.CombinedOutput()
			if err != nil {
				fail(fmt.Errorf("%w: %s", err, string(out)))
				return
			}
			succeed(strings.TrimSpace(string(out)))
		},

		"escape-mmap-denied": func(args []string) {
			// Try to mmap a file in a denied path
			f, err := os.Open(args[0])
			if err != nil {
				fail(fmt.Errorf("open: %w", err))
				return
			}
			defer f.Close()
			info, err := f.Stat()
			if err != nil {
				fail(fmt.Errorf("stat: %w", err))
				return
			}
			size := info.Size()
			if size == 0 {
				fail(fmt.Errorf("file is empty"))
				return
			}
			data, err := syscall.Mmap(int(f.Fd()), 0, int(size),
				syscall.PROT_READ, syscall.MAP_SHARED)
			if err != nil {
				fail(fmt.Errorf("mmap: %w", err))
				return
			}
			_ = data
			syscall.Munmap(data)
			succeed(fmt.Sprintf("mmapped %d bytes", size))
		},

		"escape-env-exfil": func(args []string) {
			// Check what environment variables are visible
			profile := os.Getenv("_SEATBELT_PROFILE")
			marker := os.Getenv("_SEATBELT_CHILD")
			succeed(fmt.Sprintf("marker=%s profile_len=%d", marker, len(profile)))
		},

		"escape-dev-fd": func(args []string) {
			// Try to access /dev/fd to enumerate open file descriptors
			entries, err := os.ReadDir("/dev/fd")
			if err != nil {
				fail(err)
				return
			}
			var fds []string
			for _, e := range entries {
				fds = append(fds, e.Name())
			}
			succeed(strings.Join(fds, ","))
		},

		"escape-ipc-shm": func(args []string) {
			// Try POSIX shared memory via shm_open (through syscall)
			// On macOS, shm_open is in libc, not directly a syscall.
			// We test by trying to open /dev/shm or using SHM via mmap.
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

		// ── Concurrency tests ─────────────────────────────────────

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

		"concurrent-denied": func(args []string) {
			path := args[0]
			var wg sync.WaitGroup
			denied := 0
			var mu sync.Mutex
			for i := 0; i < 100; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, err := os.ReadFile(path)
					if err != nil {
						mu.Lock()
						denied++
						mu.Unlock()
					}
				}()
			}
			wg.Wait()
			succeed(fmt.Sprintf("%d denied out of 100", denied))
		},

		// ── Lifecycle tests ───────────────────────────────────────

		"exit-code": func(args []string) {
			code := 0
			if len(args) > 0 {
				fmt.Sscanf(args[0], "%d", &code)
			}
			os.Exit(code)
		},

		"print-args": func(args []string) {
			succeed(strings.Join(os.Args, " "))
		},

		"print-env": func(args []string) {
			val := os.Getenv(args[0])
			succeed(val)
		},

		"print-cwd": func(args []string) {
			cwd, err := os.Getwd()
			if err != nil {
				fail(err)
				return
			}
			succeed(cwd)
		},

		"is-sandboxed": func(args []string) {
			marker := os.Getenv("_SEATBELT_CHILD")
			succeed(marker)
		},

		"print-runtime": func(args []string) {
			succeed(fmt.Sprintf("os=%s arch=%s", runtime.GOOS, runtime.GOARCH))
		},

		"noop": func(args []string) {
			succeed()
		},
	}

	fn, ok := tests[testName]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown test: %s\n", testName)
		fmt.Fprintf(os.Stderr, "available tests:\n")
		for name := range tests {
			fmt.Fprintf(os.Stderr, "  %s\n", name)
		}
		os.Exit(2)
	}

	fn(args)
}
