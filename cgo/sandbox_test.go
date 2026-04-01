//go:build darwin && cgo

package cgo_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/mkke/seatbelt"
)

// The cgo tests use the same sandbox_helper binary but invoke it through
// a wrapper that calls cgo.Apply before running the test function.
// This is done via a separate helper binary (testdata/cgo_helper).

type helperResult struct {
	OK   bool   `json:"ok"`
	Err  string `json:"err,omitempty"`
	Data string `json:"data,omitempty"`
}

var (
	cgoHelperBinary string
	cgoHelperOnce   sync.Once
	cgoHelperErr    error
)

func buildCgoHelper(t *testing.T) string {
	t.Helper()
	cgoHelperOnce.Do(func() {
		tmpDir, err := os.MkdirTemp("", "seatbelt-cgo-test-*")
		if err != nil {
			cgoHelperErr = fmt.Errorf("create temp dir: %w", err)
			return
		}
		cgoHelperBinary = filepath.Join(tmpDir, "cgo_helper")
		cmd := exec.Command("go", "build", "-o", cgoHelperBinary, "../testdata/cgo_helper")
		cmd.Dir = filepath.Join(projectRoot(), "cgo")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			cgoHelperErr = fmt.Errorf("build cgo_helper: %w\n%s", err, out)
			return
		}
	})
	if cgoHelperErr != nil {
		t.Skip(cgoHelperErr)
	}
	return cgoHelperBinary
}

func projectRoot() string {
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "."
		}
		dir = parent
	}
}

// runCgo runs the cgo_helper binary with a profile specification and test name.
// The helper applies the sandbox via cgo.Apply, then runs the test function.
func runCgo(t *testing.T, profileSpec string, testName string, args ...string) helperResult {
	t.Helper()
	binary := buildCgoHelper(t)

	cmdArgs := []string{profileSpec, testName}
	cmdArgs = append(cmdArgs, args...)

	cmd := exec.Command(binary, cmdArgs...)
	out, err := cmd.CombinedOutput()

	var r helperResult
	if jsonErr := json.Unmarshal(out, &r); jsonErr != nil {
		r.OK = false
		r.Err = fmt.Sprintf("exit: %v, output: %s", err, string(out))
	}
	return r
}

func expectSuccess(t *testing.T, r helperResult) {
	t.Helper()
	if !r.OK {
		t.Fatalf("expected success, got error: %s", r.Err)
	}
}

func expectDenied(t *testing.T, r helperResult) {
	t.Helper()
	if r.OK {
		t.Fatalf("expected denial, got success (data: %s)", r.Data)
	}
	errLower := strings.ToLower(r.Err)
	if !strings.Contains(errLower, "operation not permitted") &&
		!strings.Contains(errLower, "permission denied") &&
		!strings.Contains(errLower, "not permitted") &&
		!strings.Contains(errLower, "denied") {
		t.Logf("warning: unexpected error type: %s", r.Err)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// CGO APPLY TESTS
// ═══════════════════════════════════════════════════════════════════════

func TestCgo_ApplyMinimal(t *testing.T) {
	// The helper applies Minimal preset, then runs the test.
	r := runCgo(t, "minimal", "noop")
	expectSuccess(t, r)
}

func TestCgo_ApplyDeniesFileRead(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "seatbelt-cgo-deny-*")
	defer os.RemoveAll(tmpDir)
	os.WriteFile(filepath.Join(tmpDir, "secret.txt"), []byte("data"), 0644)

	r := runCgo(t, "minimal", "fs-read-file", filepath.Join(tmpDir, "secret.txt"))
	expectDenied(t, r)
}

func TestCgo_ApplyAllowsReadOnly(t *testing.T) {
	r := runCgo(t, "readonly:/etc", "fs-read-file", "/etc/hosts")
	expectSuccess(t, r)
}

func TestCgo_ApplyDeniesWriteOnReadOnly(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "seatbelt-cgo-ro-*")
	defer os.RemoveAll(tmpDir)

	r := runCgo(t, "readonly:"+tmpDir, "fs-write-file", filepath.Join(tmpDir, "blocked.txt"))
	expectDenied(t, r)
}

func TestCgo_ApplyAllowsReadWrite(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "seatbelt-cgo-rw-*")
	defer os.RemoveAll(tmpDir)

	r := runCgo(t, "readwrite:"+tmpDir, "fs-write-file", filepath.Join(tmpDir, "allowed.txt"))
	expectSuccess(t, r)
}

func TestCgo_ApplyDeniesNetwork(t *testing.T) {
	r := runCgo(t, "minimal", "net-dial-tcp", "1.1.1.1:80")
	expectDenied(t, r)
}

func TestCgo_ApplyAllowsNetwork(t *testing.T) {
	r := runCgo(t, "network", "net-dial-tcp", "1.1.1.1:80")
	expectSuccess(t, r)
}

func TestCgo_ApplyDeniesExec(t *testing.T) {
	r := runCgo(t, "minimal", "proc-exec", "/bin/echo", "hi")
	expectDenied(t, r)
}

func TestCgo_ApplyDoubleReturnError(t *testing.T) {
	// The helper tries to Apply twice; second should return an error.
	r := runCgo(t, "double", "noop")
	expectSuccess(t, r)
	// Data should indicate the double-apply error.
	if !strings.Contains(r.Data, "already sandboxed") {
		t.Fatalf("expected 'already sandboxed' in data, got: %s", r.Data)
	}
}

func TestCgo_ApplyInvalidProfile(t *testing.T) {
	r := runCgo(t, "invalid", "noop")
	// Should report a sandbox_init error.
	if r.OK {
		t.Fatal("expected error from invalid profile")
	}
	if !strings.Contains(r.Err, "sandbox_init") {
		t.Logf("error: %s", r.Err)
	}
}

func TestCgo_IsApplied(t *testing.T) {
	r := runCgo(t, "minimal", "cgo-is-applied")
	expectSuccess(t, r)
	if r.Data != "true" {
		t.Fatalf("expected IsApplied=true, got: %s", r.Data)
	}
}

func TestCgo_SysctlRead(t *testing.T) {
	r := runCgo(t, "minimal", "sysctl-read", "kern.ostype")
	expectSuccess(t, r)
	if r.Data != "Darwin" {
		t.Fatalf("expected Darwin, got: %s", r.Data)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// CGO ESCAPE TESTS
// ═══════════════════════════════════════════════════════════════════════

func TestCgo_EscapeChroot(t *testing.T) {
	r := runCgo(t, "minimal", "escape-chroot")
	expectDenied(t, r)
}

func TestCgo_EscapePtrace(t *testing.T) {
	r := runCgo(t, "minimal", "escape-ptrace")
	expectDenied(t, r)
}

func TestCgo_EscapeSymlinkPivot(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "seatbelt-cgo-escape-*")
	defer os.RemoveAll(tmpDir)

	r := runCgo(t, "readwrite:"+tmpDir, "escape-symlink-pivot", tmpDir, "/var/log/system.log")
	expectDenied(t, r)
}

func TestCgo_ProfileBuilder(t *testing.T) {
	// Verify BuildProfile works correctly from external package.
	profile, err := seatbelt.BuildProfile(
		seatbelt.NoNetwork,
		seatbelt.ReadOnly("/etc"),
	)
	if err != nil {
		t.Fatal(err)
	}
	s := profile.String()
	if !strings.Contains(s, `(import "bsd.sb")`) {
		t.Fatal("expected bsd.sb import")
	}
	if !strings.Contains(s, "file-read*") {
		t.Fatal("expected file-read* rule")
	}
	if strings.Contains(s, "(allow network") {
		t.Fatal("NoNetwork should not allow network")
	}
}
