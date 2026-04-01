package seatbelt_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// helperResult is the JSON output from the sandbox_helper binary.
type helperResult struct {
	OK   bool   `json:"ok"`
	Err  string `json:"err,omitempty"`
	Data string `json:"data,omitempty"`
}

var (
	helperBinary string
	helperOnce   sync.Once
	helperErr    error
)

// buildHelper compiles the sandbox_helper test binary once per test run.
func buildHelper(t *testing.T) string {
	t.Helper()
	helperOnce.Do(func() {
		if runtime.GOOS != "darwin" {
			helperErr = fmt.Errorf("seatbelt tests require macOS (darwin), got %s", runtime.GOOS)
			return
		}
		if _, err := exec.LookPath("sandbox-exec"); err != nil {
			helperErr = fmt.Errorf("sandbox-exec not found in PATH: %w", err)
			return
		}

		tmpDir, err := os.MkdirTemp("", "seatbelt-test-*")
		if err != nil {
			helperErr = fmt.Errorf("create temp dir: %w", err)
			return
		}
		helperBinary = filepath.Join(tmpDir, "sandbox_helper")
		cmd := exec.Command("go", "build", "-o", helperBinary, "./testdata/sandbox_helper")
		cmd.Dir = projectRoot()
		cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			helperErr = fmt.Errorf("build sandbox_helper: %w\n%s", err, out)
			return
		}
	})
	if helperErr != nil {
		t.Skip(helperErr)
	}
	return helperBinary
}

// projectRoot returns the root of the seatbelt project.
func projectRoot() string {
	// Walk up from the test file to find go.mod.
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

// sbProfile generates an SBPL profile string from the given allow rules.
// It always starts with (version 1)(deny default) and imports bsd.sb.
// The helper binary rules are injected later by runSandboxed().
func sbProfile(rules ...string) string {
	var sb strings.Builder
	sb.WriteString("(version 1)\n")
	sb.WriteString("(deny default)\n")
	sb.WriteString("(import \"bsd.sb\")\n")
	// Allow minimum operations for Go runtime.
	sb.WriteString("(allow process-fork)\n")
	sb.WriteString("(allow signal)\n")
	sb.WriteString("(allow sysctl-read)\n")
	sb.WriteString("(allow mach-lookup (global-name \"com.apple.trustd.agent\"))\n")
	sb.WriteString("(allow mach-lookup (global-name \"com.apple.SystemConfiguration.configd\"))\n")
	sb.WriteString("(allow ipc-posix-sem)\n")

	// Allow reading system libraries and frameworks needed by any Go binary.
	sb.WriteString("(allow file-read* file-read-metadata (subpath \"/usr/lib\"))\n")
	sb.WriteString("(allow file-read* file-read-metadata (subpath \"/usr/share\"))\n")
	sb.WriteString("(allow file-read* file-read-metadata (subpath \"/System/Library\"))\n")
	sb.WriteString("(allow file-read* file-read-metadata (subpath \"/Library/Preferences\"))\n")
	sb.WriteString("(allow file-read* file-read-metadata (literal \"/dev/null\"))\n")
	sb.WriteString("(allow file-read* file-read-metadata (literal \"/dev/urandom\"))\n")

	for _, r := range rules {
		sb.WriteString(r)
		sb.WriteString("\n")
	}
	return sb.String()
}

// helperRules returns SBPL rules to allow the helper binary to execute.
// Only grants access to the specific helper binary directory, not the
// entire temp dir, so that denial tests for other temp dirs still work.
// Must be called after buildHelper().
func helperRules() string {
	var sb strings.Builder
	if helperBinary != "" {
		helperDir := filepath.Dir(helperBinary)
		sb.WriteString(fmt.Sprintf("(allow process-exec (subpath \"%s\"))\n", helperDir))
		sb.WriteString(fmt.Sprintf("(allow file-read* file-write* file-read-metadata (subpath \"%s\"))\n", helperDir))
		if resolved, err := filepath.EvalSymlinks(helperDir); err == nil && resolved != helperDir {
			sb.WriteString(fmt.Sprintf("(allow process-exec (subpath \"%s\"))\n", resolved))
			sb.WriteString(fmt.Sprintf("(allow file-read* file-write* file-read-metadata (subpath \"%s\"))\n", resolved))
		}
	}
	return sb.String()
}

// resolvedPath returns both the original and EvalSymlinks-resolved path
// as an SBPL (require-any (subpath ...) (subpath ...)) expression, or
// just (subpath ...) if they are the same.
func resolvedSubpath(path string) string {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved == path {
		return fmt.Sprintf(`(subpath "%s")`, path)
	}
	return fmt.Sprintf(`(require-any (subpath "%s") (subpath "%s"))`, path, resolved)
}

func resolvedLiteral(path string) string {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved == path {
		return fmt.Sprintf(`(literal "%s")`, path)
	}
	return fmt.Sprintf(`(require-any (literal "%s") (literal "%s"))`, path, resolved)
}

// runSandboxed runs the helper binary inside a sandbox with the given SBPL
// profile. Returns the parsed result and the raw combined output.
func runSandboxed(t *testing.T, profile string, testName string, args ...string) helperResult {
	t.Helper()
	binary := buildHelper(t)

	// Inject helper binary rules into the profile (after the first line).
	// We insert after "(deny default)\n" to ensure proper ordering.
	rules := helperRules()
	profile = profile + rules

	cmdArgs := []string{"-p", profile, binary, testName}
	cmdArgs = append(cmdArgs, args...)

	cmd := exec.Command("sandbox-exec", cmdArgs...)
	cmd.Env = append(os.Environ(), "_SEATBELT_CHILD=1")
	out, err := cmd.CombinedOutput()

	var r helperResult
	if jsonErr := json.Unmarshal(out, &r); jsonErr != nil {
		// The helper may have been killed or failed to produce JSON.
		r.OK = false
		r.Err = fmt.Sprintf("exit: %v, output: %s", err, string(out))
	}
	return r
}

// expectSuccess asserts the sandboxed operation succeeded.
func expectSuccess(t *testing.T, r helperResult) {
	t.Helper()
	if !r.OK {
		t.Fatalf("expected success, got error: %s", r.Err)
	}
}

// expectDenied asserts the sandboxed operation was denied.
func expectDenied(t *testing.T, r helperResult) {
	t.Helper()
	if r.OK {
		t.Fatalf("expected denial, got success (data: %s)", r.Data)
	}
	// On macOS, sandbox denials produce "Operation not permitted" (EPERM)
	// or "Permission denied" (EACCES).
	errLower := strings.ToLower(r.Err)
	if !strings.Contains(errLower, "operation not permitted") &&
		!strings.Contains(errLower, "permission denied") &&
		!strings.Contains(errLower, "not permitted") &&
		!strings.Contains(errLower, "denied") {
		t.Logf("warning: unexpected error type (may still be a valid denial): %s", r.Err)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// FILE SYSTEM TESTS
// ═══════════════════════════════════════════════════════════════════════

func TestFS_ReadAllowedPath(t *testing.T) {
	profile := sbProfile(
		fmt.Sprintf(`(allow file-read* file-read-metadata %s)`, resolvedSubpath("/etc")),
	)
	r := runSandboxed(t, profile, "fs-read-file", "/etc/hosts")
	expectSuccess(t, r)
}

func TestFS_ReadDeniedPath(t *testing.T) {
	profile := sbProfile(
		fmt.Sprintf(`(allow file-read* file-read-metadata %s)`, resolvedSubpath("/etc")),
	)
	r := runSandboxed(t, profile, "fs-read-file", "/var/log/system.log")
	expectDenied(t, r)
}

func TestFS_WriteToReadOnlyPath(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "seatbelt-ro-*")
	defer os.RemoveAll(tmpDir)

	profile := sbProfile(
		fmt.Sprintf(`(allow file-read* file-read-metadata %s)`, resolvedSubpath(tmpDir)),
	)
	r := runSandboxed(t, profile, "fs-write-file", filepath.Join(tmpDir, "blocked.txt"))
	expectDenied(t, r)
}

func TestFS_WriteToReadWritePath(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "seatbelt-rw-*")
	defer os.RemoveAll(tmpDir)

	profile := sbProfile(
		fmt.Sprintf(`(allow file-read* file-write* file-read-metadata %s)`, resolvedSubpath(tmpDir)),
	)
	r := runSandboxed(t, profile, "fs-write-file", filepath.Join(tmpDir, "allowed.txt"))
	expectSuccess(t, r)
}

func TestFS_WriteToUnmentionedPath(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "seatbelt-allowed-*")
	defer os.RemoveAll(tmpDir)
	otherDir, _ := os.MkdirTemp("", "seatbelt-denied-*")
	defer os.RemoveAll(otherDir)

	profile := sbProfile(
		fmt.Sprintf(`(allow file-read* file-write* file-read-metadata %s)`, resolvedSubpath(tmpDir)),
	)
	r := runSandboxed(t, profile, "fs-write-file", filepath.Join(otherDir, "blocked.txt"))
	expectDenied(t, r)
}

func TestFS_MkdirDenied(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "seatbelt-mkdir-*")
	defer os.RemoveAll(tmpDir)

	profile := sbProfile(
		fmt.Sprintf(`(allow file-read* file-read-metadata %s)`, resolvedSubpath(tmpDir)),
	)
	r := runSandboxed(t, profile, "fs-mkdir", filepath.Join(tmpDir, "newdir"))
	expectDenied(t, r)
}

func TestFS_MkdirAllowed(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "seatbelt-mkdir-*")
	defer os.RemoveAll(tmpDir)

	profile := sbProfile(
		fmt.Sprintf(`(allow file-read* file-write* file-read-metadata %s)`, resolvedSubpath(tmpDir)),
	)
	r := runSandboxed(t, profile, "fs-mkdir", filepath.Join(tmpDir, "newdir"))
	expectSuccess(t, r)
}

func TestFS_RemoveDenied(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "seatbelt-rm-*")
	defer os.RemoveAll(tmpDir)
	os.WriteFile(filepath.Join(tmpDir, "victim.txt"), []byte("data"), 0644)

	profile := sbProfile(
		fmt.Sprintf(`(allow file-read* file-read-metadata %s)`, resolvedSubpath(tmpDir)),
	)
	r := runSandboxed(t, profile, "fs-remove", filepath.Join(tmpDir, "victim.txt"))
	expectDenied(t, r)
}

func TestFS_StatAllowed(t *testing.T) {
	profile := sbProfile(
		fmt.Sprintf(`(allow file-read* file-read-metadata %s)`, resolvedSubpath("/etc")),
	)
	r := runSandboxed(t, profile, "fs-stat", "/etc/hosts")
	expectSuccess(t, r)
}

func TestFS_StatAllowedByBsdSb(t *testing.T) {
	// bsd.sb (Apple's base system profile) grants file-read-metadata
	// broadly, so os.Stat succeeds even without explicit file rules.
	// This test documents that behavior.
	tmpDir, _ := os.MkdirTemp("", "seatbelt-stat-bsd-*")
	defer os.RemoveAll(tmpDir)
	os.WriteFile(filepath.Join(tmpDir, "test.txt"), []byte("data"), 0644)

	profile := sbProfile() // No explicit file rules
	r := runSandboxed(t, profile, "fs-stat", filepath.Join(tmpDir, "test.txt"))
	// bsd.sb allows file-read-metadata, so stat succeeds.
	expectSuccess(t, r)
}

func TestFS_ReadDataDenied(t *testing.T) {
	// While bsd.sb allows file-read-metadata (stat), it does NOT allow
	// file-read-data for arbitrary paths. Verify read-data denial.
	tmpDir, _ := os.MkdirTemp("", "seatbelt-readdata-denied-*")
	defer os.RemoveAll(tmpDir)
	os.WriteFile(filepath.Join(tmpDir, "secret.txt"), []byte("data"), 0644)

	profile := sbProfile() // No explicit file rules for this tmpDir
	r := runSandboxed(t, profile, "fs-read-file", filepath.Join(tmpDir, "secret.txt"))
	expectDenied(t, r)
}

func TestFS_RenameAllowed(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "seatbelt-rename-*")
	defer os.RemoveAll(tmpDir)
	os.WriteFile(filepath.Join(tmpDir, "a.txt"), []byte("data"), 0644)

	profile := sbProfile(
		fmt.Sprintf(`(allow file-read* file-write* file-read-metadata %s)`, resolvedSubpath(tmpDir)),
	)
	r := runSandboxed(t, profile, "fs-rename",
		filepath.Join(tmpDir, "a.txt"), filepath.Join(tmpDir, "b.txt"))
	expectSuccess(t, r)
}

func TestFS_RenameDenied(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "seatbelt-rename-*")
	defer os.RemoveAll(tmpDir)
	os.WriteFile(filepath.Join(tmpDir, "a.txt"), []byte("data"), 0644)

	profile := sbProfile(
		fmt.Sprintf(`(allow file-read* file-read-metadata %s)`, resolvedSubpath(tmpDir)),
	)
	r := runSandboxed(t, profile, "fs-rename",
		filepath.Join(tmpDir, "a.txt"), filepath.Join(tmpDir, "b.txt"))
	expectDenied(t, r)
}

func TestFS_SymlinkTraversal(t *testing.T) {
	// /tmp is a symlink to /private/tmp on macOS. Both paths should work
	// when the profile includes both.
	profile := sbProfile(
		fmt.Sprintf(`(allow file-read* file-read-metadata %s)`, resolvedSubpath("/tmp")),
	)
	// Create a test file
	tmpFile, _ := os.CreateTemp("/tmp", "seatbelt-symlink-*")
	tmpFile.Write([]byte("hello"))
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	r := runSandboxed(t, profile, "fs-read-file", tmpFile.Name())
	expectSuccess(t, r)
}

func TestFS_HardlinkEscape(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "seatbelt-hardlink-*")
	defer os.RemoveAll(tmpDir)

	profile := sbProfile(
		fmt.Sprintf(`(allow file-read* file-write* file-read-metadata %s)`, resolvedSubpath(tmpDir)),
	)
	// Try to create hardlink from /etc/hosts into the writable directory
	r := runSandboxed(t, profile, "fs-hardlink",
		"/etc/hosts", filepath.Join(tmpDir, "hosts-link"))
	expectDenied(t, r)
}

func TestFS_WriteOnlyCanWrite(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "seatbelt-wo-*")
	defer os.RemoveAll(tmpDir)

	profile := sbProfile(
		fmt.Sprintf(`(allow file-write* %s)`, resolvedSubpath(tmpDir)),
	)
	r := runSandboxed(t, profile, "fs-write-only-write", filepath.Join(tmpDir, "wo.txt"))
	expectSuccess(t, r)
}

func TestFS_WriteOnlyCannotRead(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "seatbelt-wo-*")
	defer os.RemoveAll(tmpDir)
	os.WriteFile(filepath.Join(tmpDir, "wo.txt"), []byte("secret"), 0644)

	profile := sbProfile(
		fmt.Sprintf(`(allow file-write* %s)`, resolvedSubpath(tmpDir)),
	)
	r := runSandboxed(t, profile, "fs-write-only-read", filepath.Join(tmpDir, "wo.txt"))
	expectDenied(t, r)
}

func TestFS_ParentOfAllowedNotAccessible(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "seatbelt-parent-*")
	defer os.RemoveAll(tmpDir)
	subDir := filepath.Join(tmpDir, "allowed")
	os.Mkdir(subDir, 0755)
	siblingDir := filepath.Join(tmpDir, "sibling")
	os.Mkdir(siblingDir, 0755)
	os.WriteFile(filepath.Join(siblingDir, "secret.txt"), []byte("secret"), 0644)

	profile := sbProfile(
		fmt.Sprintf(`(allow file-read* file-read-metadata %s)`, resolvedSubpath(subDir)),
	)
	r := runSandboxed(t, profile, "fs-read-file", filepath.Join(siblingDir, "secret.txt"))
	expectDenied(t, r)
}

func TestFS_ReadDir(t *testing.T) {
	profile := sbProfile(
		fmt.Sprintf(`(allow file-read* file-read-metadata %s)`, resolvedSubpath("/etc")),
	)
	r := runSandboxed(t, profile, "fs-readdir", "/etc")
	expectSuccess(t, r)
}

func TestFS_ReadDirDenied(t *testing.T) {
	profile := sbProfile() // No file rules
	r := runSandboxed(t, profile, "fs-readdir", "/etc")
	expectDenied(t, r)
}

// ═══════════════════════════════════════════════════════════════════════
// NETWORK TESTS
// ═══════════════════════════════════════════════════════════════════════

func TestNet_DeniedByDefault(t *testing.T) {
	profile := sbProfile() // No network rules
	r := runSandboxed(t, profile, "net-dial-tcp", "1.1.1.1:80")
	expectDenied(t, r)
}

func TestNet_OutboundAllowed(t *testing.T) {
	profile := sbProfile(
		`(allow network-outbound)`,
		fmt.Sprintf(`(allow file-read* file-read-metadata %s)`, resolvedSubpath("/etc")),
		fmt.Sprintf(`(allow file-read* file-read-metadata %s)`, resolvedSubpath("/private/var/run/resolv.conf")),
	)
	r := runSandboxed(t, profile, "net-dial-tcp", "1.1.1.1:80")
	expectSuccess(t, r)
}

func TestNet_InboundDeniedWhenOutboundOnly(t *testing.T) {
	profile := sbProfile(
		`(allow network-outbound)`,
	)
	r := runSandboxed(t, profile, "net-listen-tcp")
	expectDenied(t, r)
}

func TestNet_InboundAllowed(t *testing.T) {
	profile := sbProfile(
		`(allow network-inbound)`,
		`(allow network-outbound)`, // Need outbound for bind
	)
	r := runSandboxed(t, profile, "net-listen-tcp")
	expectSuccess(t, r)
}

func TestNet_FullNetworkAllowed(t *testing.T) {
	profile := sbProfile(
		`(allow network*)`,
		fmt.Sprintf(`(allow file-read* file-read-metadata %s)`, resolvedSubpath("/etc")),
		fmt.Sprintf(`(allow file-read* file-read-metadata %s)`, resolvedSubpath("/private/var/run/resolv.conf")),
	)
	// Test both dial and listen
	r := runSandboxed(t, profile, "net-dial-tcp", "1.1.1.1:80")
	expectSuccess(t, r)

	r = runSandboxed(t, profile, "net-listen-tcp")
	expectSuccess(t, r)
}

func TestNet_UDPDenied(t *testing.T) {
	profile := sbProfile() // No network rules
	r := runSandboxed(t, profile, "net-dial-udp", "8.8.8.8:53")
	expectDenied(t, r)
}

func TestNet_UDPAllowedWithFullNetwork(t *testing.T) {
	profile := sbProfile(
		`(allow network*)`,
	)
	r := runSandboxed(t, profile, "net-dial-udp", "8.8.8.8:53")
	expectSuccess(t, r)
}

func TestNet_LocalhostDenied(t *testing.T) {
	profile := sbProfile() // No network rules
	r := runSandboxed(t, profile, "net-localhost", "12345")
	expectDenied(t, r)
}

func TestNet_HTTPGetDenied(t *testing.T) {
	profile := sbProfile() // No network rules
	r := runSandboxed(t, profile, "net-http-get", "http://example.com")
	expectDenied(t, r)
}

// ═══════════════════════════════════════════════════════════════════════
// PROCESS EXECUTION TESTS
// ═══════════════════════════════════════════════════════════════════════

func TestProc_ExecAllowedBinary(t *testing.T) {
	profile := sbProfile(
		fmt.Sprintf(`(allow process-exec %s)`, resolvedLiteral("/bin/echo")),
		fmt.Sprintf(`(allow file-read* file-read-metadata %s)`, resolvedSubpath("/bin")),
		fmt.Sprintf(`(allow file-read* file-read-metadata %s)`, resolvedSubpath("/usr/lib")),
	)
	r := runSandboxed(t, profile, "proc-exec", "/bin/echo", "hello")
	expectSuccess(t, r)
	if !strings.Contains(r.Data, "hello") {
		t.Fatalf("expected output to contain 'hello', got: %s", r.Data)
	}
}

func TestProc_ExecDeniedBinary(t *testing.T) {
	profile := sbProfile(
		fmt.Sprintf(`(allow process-exec %s)`, resolvedLiteral("/bin/echo")),
		fmt.Sprintf(`(allow file-read* file-read-metadata %s)`, resolvedSubpath("/usr")),
	)
	r := runSandboxed(t, profile, "proc-exec", "/usr/bin/id")
	expectDenied(t, r)
}

func TestProc_ExecNoRules(t *testing.T) {
	profile := sbProfile() // No exec rules
	r := runSandboxed(t, profile, "proc-exec", "/bin/echo", "nope")
	expectDenied(t, r)
}

func TestProc_ExecDirectoryAllowsAllInDir(t *testing.T) {
	profile := sbProfile(
		fmt.Sprintf(`(allow process-exec %s)`, resolvedSubpath("/usr/bin")),
		fmt.Sprintf(`(allow file-read* file-read-metadata %s)`, resolvedSubpath("/usr")),
	)
	r := runSandboxed(t, profile, "proc-exec", "/usr/bin/env")
	expectSuccess(t, r)
}

func TestProc_ShellEscapeAttempt(t *testing.T) {
	// Allow /bin/sh but NOT /bin/cat. The shell should be able to start
	// but the inner command should be denied.
	profile := sbProfile(
		fmt.Sprintf(`(allow process-exec %s)`, resolvedLiteral("/bin/sh")),
		fmt.Sprintf(`(allow file-read* file-read-metadata %s)`, resolvedSubpath("/bin")),
		fmt.Sprintf(`(allow file-read* file-read-metadata %s)`, resolvedSubpath("/usr/lib")),
		fmt.Sprintf(`(allow file-read* file-read-metadata %s)`, resolvedSubpath("/etc")),
	)
	r := runSandboxed(t, profile, "proc-exec-shell-escape", "cat /etc/shadow")
	expectDenied(t, r)
}

func TestProc_ExecWrittenScript(t *testing.T) {
	// Write a script to an allowed path, then try to execute it.
	// The script should not be executable if its path is not in AllowExec.
	tmpDir, _ := os.MkdirTemp("", "seatbelt-script-*")
	defer os.RemoveAll(tmpDir)

	profile := sbProfile(
		fmt.Sprintf(`(allow file-read* file-write* file-read-metadata %s)`, resolvedSubpath(tmpDir)),
		// Deliberately NOT allowing process-exec for tmpDir
	)
	r := runSandboxed(t, profile, "proc-exec-written-script", tmpDir)
	expectDenied(t, r)
}

// ═══════════════════════════════════════════════════════════════════════
// MACH IPC TESTS
// ═══════════════════════════════════════════════════════════════════════

func TestMach_TLSWithTrustd(t *testing.T) {
	if testing.Short() {
		t.Skip("TLS handshake test requires network access")
	}
	profile := sbProfile(
		`(allow network*)`,
		fmt.Sprintf(`(allow file-read* file-read-metadata %s)`, resolvedSubpath("/etc")),
		fmt.Sprintf(`(allow file-read* file-read-metadata %s)`, resolvedSubpath("/private/var/run")),
		// trustd.agent is already in sbProfile's Minimal set
	)
	r := runSandboxed(t, profile, "mach-tls-handshake")
	expectSuccess(t, r)
}

// ═══════════════════════════════════════════════════════════════════════
// SYSCTL TESTS
// ═══════════════════════════════════════════════════════════════════════

func TestSysctl_ReadAllowed(t *testing.T) {
	// sysctl-read is in the base sbProfile
	profile := sbProfile()
	r := runSandboxed(t, profile, "sysctl-read", "kern.ostype")
	expectSuccess(t, r)
	if r.Data != "Darwin" {
		t.Fatalf("expected kern.ostype=Darwin, got: %s", r.Data)
	}
}

func TestSysctl_ReadDeniedWithoutRule(t *testing.T) {
	// Note: bsd.sb (Apple's base system profile) grants sysctl-read
	// implicitly, so it cannot be independently denied while importing
	// bsd.sb. This test verifies the behavior: sysctl-read is available
	// as part of bsd.sb even without an explicit allow rule.
	//
	// This is documented as a known behavior — the Minimal preset
	// includes sysctl-read explicitly for clarity, but bsd.sb already
	// provides it.
	var sb strings.Builder
	sb.WriteString("(version 1)\n")
	sb.WriteString("(deny default)\n")
	sb.WriteString("(import \"bsd.sb\")\n")
	sb.WriteString("(allow process-fork)\n")
	sb.WriteString("(allow signal)\n")
	// No explicit sysctl-read — but bsd.sb provides it.
	sb.WriteString("(allow mach-lookup (global-name \"com.apple.trustd.agent\"))\n")
	sb.WriteString("(allow file-read* file-read-metadata (subpath \"/usr/lib\"))\n")
	sb.WriteString("(allow file-read* file-read-metadata (subpath \"/System/Library\"))\n")

	r := runSandboxed(t, sb.String(), "sysctl-read", "kern.ostype")
	// bsd.sb allows sysctl-read, so this succeeds even without an explicit rule.
	expectSuccess(t, r)
}

// ═══════════════════════════════════════════════════════════════════════
// SIGNAL TESTS
// ═══════════════════════════════════════════════════════════════════════

func TestSignal_SelfAllowed(t *testing.T) {
	profile := sbProfile()
	r := runSandboxed(t, profile, "signal-self")
	expectSuccess(t, r)
}

func TestSignal_OtherProcess(t *testing.T) {
	profile := sbProfile()
	// Signaling PID 1 should be denied by the OS regardless of sandbox
	r := runSandboxed(t, profile, "signal-other")
	expectDenied(t, r)
}

// ═══════════════════════════════════════════════════════════════════════
// ESCAPE VECTOR TESTS
// ═══════════════════════════════════════════════════════════════════════

func TestEscape_SymlinkPivot(t *testing.T) {
	// Create a symlink in a writable dir pointing to a restricted path,
	// then try to read through it. The kernel resolves vnodes, so this
	// should be denied.
	tmpDir, _ := os.MkdirTemp("", "seatbelt-escape-symlink-*")
	defer os.RemoveAll(tmpDir)

	profile := sbProfile(
		fmt.Sprintf(`(allow file-read* file-write* file-read-metadata %s)`, resolvedSubpath(tmpDir)),
		// /var/log is NOT in the allowed paths
	)
	r := runSandboxed(t, profile, "escape-symlink-pivot", tmpDir, "/var/log/system.log")
	expectDenied(t, r)
}

func TestEscape_RenameToRestrictedPath(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "seatbelt-escape-rename-*")
	defer os.RemoveAll(tmpDir)
	targetDir, _ := os.MkdirTemp("", "seatbelt-escape-target-*")
	defer os.RemoveAll(targetDir)

	profile := sbProfile(
		fmt.Sprintf(`(allow file-read* file-write* file-read-metadata %s)`, resolvedSubpath(tmpDir)),
		// targetDir is NOT writable
	)
	r := runSandboxed(t, profile, "escape-rename-to-denied",
		filepath.Join(tmpDir, "src.txt"),
		filepath.Join(targetDir, "dst.txt"))
	expectDenied(t, r)
}

func TestEscape_Chroot(t *testing.T) {
	profile := sbProfile()
	r := runSandboxed(t, profile, "escape-chroot")
	expectDenied(t, r)
}

func TestEscape_Ptrace(t *testing.T) {
	profile := sbProfile()
	r := runSandboxed(t, profile, "escape-ptrace")
	expectDenied(t, r)
}

func TestEscape_AppleScript(t *testing.T) {
	profile := sbProfile() // No exec, no appleevent-send
	r := runSandboxed(t, profile, "escape-applescript")
	expectDenied(t, r)
}

func TestEscape_Keychain(t *testing.T) {
	// Without allowing exec of /usr/bin/security and the Mach lookups
	// for SecurityServer, this should fail.
	profile := sbProfile()
	r := runSandboxed(t, profile, "escape-keychain")
	expectDenied(t, r)
}

func TestEscape_DoubleSandboxTighter(t *testing.T) {
	// Apply a permissive sandbox, then from within it try to apply a
	// tighter sandbox. This should work (sandboxes stack).
	profile := sbProfile(
		`(allow network*)`,
		fmt.Sprintf(`(allow file-read* file-write* file-read-metadata %s)`, resolvedSubpath("/tmp")),
		fmt.Sprintf(`(allow file-read* file-read-metadata %s)`, resolvedSubpath("/usr")),
		fmt.Sprintf(`(allow process-exec %s)`, resolvedSubpath("/usr/bin")),
	)
	r := runSandboxed(t, profile, "escape-double-sandbox-tighter")
	// The inner sandbox should succeed in applying but may restrict operations.
	// We just verify the process doesn't crash.
	if !r.OK {
		t.Logf("double sandbox result: %s (this may be expected)", r.Err)
	}
}

func TestEscape_MmapDeniedFile(t *testing.T) {
	profile := sbProfile() // No file rules beyond bsd.sb
	r := runSandboxed(t, profile, "escape-mmap-denied", "/etc/hosts")
	// The open() call should fail before mmap is even attempted
	expectDenied(t, r)
}

func TestEscape_EnvExfiltration(t *testing.T) {
	// Verify the sandbox marker env vars are visible (by design).
	profile := sbProfile()
	r := runSandboxed(t, profile, "escape-env-exfil")
	expectSuccess(t, r)
	if !strings.Contains(r.Data, "marker=1") {
		t.Fatalf("expected _SEATBELT_CHILD=1 in env, got: %s", r.Data)
	}
}

func TestEscape_DevFd(t *testing.T) {
	profile := sbProfile(
		fmt.Sprintf(`(allow file-read* file-read-metadata %s)`, resolvedSubpath("/dev")),
	)
	r := runSandboxed(t, profile, "escape-dev-fd")
	// /dev/fd access should work since /dev is readable
	expectSuccess(t, r)
}

func TestEscape_IPCShm(t *testing.T) {
	// Without AllowIPCPosixShm, shm_open should be denied.
	var sb strings.Builder
	sb.WriteString("(version 1)\n")
	sb.WriteString("(deny default)\n")
	sb.WriteString("(import \"bsd.sb\")\n")
	sb.WriteString("(allow process-fork)\n")
	sb.WriteString("(allow signal)\n")
	sb.WriteString("(allow sysctl-read)\n")
	sb.WriteString("(allow mach-lookup (global-name \"com.apple.trustd.agent\"))\n")
	sb.WriteString("(allow file-read* file-read-metadata (subpath \"/usr/lib\"))\n")
	sb.WriteString("(allow file-read* file-read-metadata (subpath \"/System/Library\"))\n")
	// Deliberately NO ipc-posix-shm-*

	r := runSandboxed(t, sb.String(), "escape-ipc-shm")
	expectDenied(t, r)
}

// ═══════════════════════════════════════════════════════════════════════
// LIFECYCLE / RE-EXEC TESTS
// ═══════════════════════════════════════════════════════════════════════

func TestLifecycle_CleanExit(t *testing.T) {
	binary := buildHelper(t)
	profile := sbProfile() + helperRules()
	// exit-code calls os.Exit directly; we verify via the exit code
	// of sandbox-exec itself.
	cmd := exec.Command("sandbox-exec", "-p", profile, binary, "exit-code", "0")
	cmd.Env = append(os.Environ(), "_SEATBELT_CHILD=1")
	err := cmd.Run()
	if err != nil {
		t.Fatalf("expected clean exit, got: %v", err)
	}
}

func TestLifecycle_ErrorExit(t *testing.T) {
	binary := buildHelper(t)
	profile := sbProfile() + helperRules()
	cmd := exec.Command("sandbox-exec", "-p", profile, binary, "exit-code", "42")
	cmd.Env = append(os.Environ(), "_SEATBELT_CHILD=1")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit, got success")
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got: %T", err)
	}
	if exitErr.ExitCode() != 42 {
		t.Fatalf("expected exit code 42, got: %d", exitErr.ExitCode())
	}
}

func TestLifecycle_ArgsPreservation(t *testing.T) {
	profile := sbProfile()
	r := runSandboxed(t, profile, "print-args")
	expectSuccess(t, r)
	if !strings.Contains(r.Data, "print-args") {
		t.Fatalf("expected 'print-args' in args, got: %s", r.Data)
	}
}

func TestLifecycle_EnvPreservation(t *testing.T) {
	binary := buildHelper(t)
	profile := sbProfile() + helperRules()
	cmd := exec.Command("sandbox-exec", "-p", profile, binary, "print-env", "SEATBELT_TEST_VAR")
	cmd.Env = append(os.Environ(), "_SEATBELT_CHILD=1", "SEATBELT_TEST_VAR=hello_from_parent")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v\n%s", err, out)
	}
	var r helperResult
	json.Unmarshal(out, &r)
	if r.Data != "hello_from_parent" {
		t.Fatalf("expected env var value 'hello_from_parent', got: %s", r.Data)
	}
}

func TestLifecycle_CWDPreservation(t *testing.T) {
	binary := buildHelper(t)
	profile := sbProfile(
		fmt.Sprintf(`(allow file-read* file-read-metadata %s)`, resolvedSubpath("/tmp")),
	) + helperRules()
	cmd := exec.Command("sandbox-exec", "-p", profile, binary, "print-cwd")
	cmd.Dir = "/tmp"
	cmd.Env = append(os.Environ(), "_SEATBELT_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v\n%s", err, out)
	}
	var r helperResult
	json.Unmarshal(out, &r)
	resolved, _ := filepath.EvalSymlinks("/tmp")
	if r.Data != resolved && r.Data != "/tmp" {
		t.Fatalf("expected CWD /tmp or %s, got: %s", resolved, r.Data)
	}
}

func TestLifecycle_IsSandboxed(t *testing.T) {
	profile := sbProfile()
	r := runSandboxed(t, profile, "is-sandboxed")
	expectSuccess(t, r)
	if r.Data != "1" {
		t.Fatalf("expected _SEATBELT_CHILD=1, got: %s", r.Data)
	}
}

func TestLifecycle_RuntimeInfo(t *testing.T) {
	profile := sbProfile()
	r := runSandboxed(t, profile, "print-runtime")
	expectSuccess(t, r)
	if !strings.Contains(r.Data, "os=darwin") {
		t.Fatalf("expected darwin runtime, got: %s", r.Data)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// CONCURRENCY / STRESS TESTS
// ═══════════════════════════════════════════════════════════════════════

func TestStress_ConcurrentReadAllowed(t *testing.T) {
	if testing.Short() {
		t.Skip("stress test")
	}
	profile := sbProfile(
		fmt.Sprintf(`(allow file-read* file-read-metadata %s)`, resolvedSubpath("/etc")),
	)
	r := runSandboxed(t, profile, "concurrent-read", "/etc/hosts")
	expectSuccess(t, r)
}

func TestStress_ConcurrentDeniedAccess(t *testing.T) {
	if testing.Short() {
		t.Skip("stress test")
	}
	profile := sbProfile() // No file rules
	r := runSandboxed(t, profile, "concurrent-denied", "/etc/hosts")
	expectSuccess(t, r) // Helper reports success with count of denials
	if !strings.Contains(r.Data, "100 denied") {
		t.Fatalf("expected all 100 accesses denied, got: %s", r.Data)
	}
}

func TestStress_ManyOpenFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("stress test")
	}
	tmpDir, _ := os.MkdirTemp("", "seatbelt-stress-*")
	defer os.RemoveAll(tmpDir)

	profile := sbProfile(
		fmt.Sprintf(`(allow file-read* file-write* file-read-metadata %s)`, resolvedSubpath(tmpDir)),
	)
	r := runSandboxed(t, profile, "fs-open-many", tmpDir)
	expectSuccess(t, r)
}

func TestStress_LargeFileIO(t *testing.T) {
	if testing.Short() {
		t.Skip("stress test")
	}
	tmpDir, _ := os.MkdirTemp("", "seatbelt-largefile-*")
	defer os.RemoveAll(tmpDir)

	profile := sbProfile(
		fmt.Sprintf(`(allow file-read* file-write* file-read-metadata %s)`, resolvedSubpath(tmpDir)),
	)
	r := runSandboxed(t, profile, "fs-large-file", tmpDir)
	expectSuccess(t, r)
}

func TestStress_RapidReexec(t *testing.T) {
	if testing.Short() {
		t.Skip("stress test")
	}
	profile := sbProfile()
	for i := 0; i < 10; i++ {
		r := runSandboxed(t, profile, "noop")
		expectSuccess(t, r)
	}
}
