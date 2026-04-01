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

	"github.com/mkke/seatbelt"
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

// buildProfile builds an SBPL profile from seatbelt rules, automatically
// adding rules for the helper binary to execute.
func buildProfile(t *testing.T, rules ...seatbelt.Rule) string {
	t.Helper()
	binary := buildHelper(t)
	helperDir := filepath.Dir(binary)

	// Build the helper access rules.
	helperAccess := []seatbelt.Rule{
		seatbelt.AllowExec(helperDir),
		seatbelt.ReadWrite(helperDir),
		// System libraries needed by any Go binary.
		seatbelt.ReadOnly("/usr/lib", "/usr/share", "/System/Library", "/Library/Preferences"),
		seatbelt.Custom(`(allow file-read* file-read-metadata (literal "/dev/null"))`),
		seatbelt.Custom(`(allow file-read* file-read-metadata (literal "/dev/urandom"))`),
	}

	all := append(helperAccess, rules...)
	profile, err := seatbelt.BuildProfile(all...)
	if err != nil {
		t.Fatalf("BuildProfile: %v", err)
	}
	return profile.String()
}

// runSandboxed runs the helper binary inside a sandbox with the given rules.
func runSandboxed(t *testing.T, profile string, testName string, args ...string) helperResult {
	t.Helper()
	binary := buildHelper(t)

	cmdArgs := []string{"-p", profile, binary, testName}
	cmdArgs = append(cmdArgs, args...)

	cmd := exec.Command("sandbox-exec", cmdArgs...)
	cmd.Env = append(os.Environ(), "_SEATBELT_CHILD=1")
	out, err := cmd.CombinedOutput()

	var r helperResult
	if jsonErr := json.Unmarshal(out, &r); jsonErr != nil {
		r.OK = false
		r.Err = fmt.Sprintf("exit: %v, output: %s", err, string(out))
	}
	return r
}

// runWithRules builds a profile from rules and runs the helper.
func runWithRules(t *testing.T, rules []seatbelt.Rule, testName string, args ...string) helperResult {
	t.Helper()
	profile := buildProfile(t, rules...)
	return runSandboxed(t, profile, testName, args...)
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
		t.Logf("warning: unexpected error type (may still be a valid denial): %s", r.Err)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// PROFILE BUILDER TESTS
// ═══════════════════════════════════════════════════════════════════════

func TestBuildProfile_NoRules(t *testing.T) {
	_, err := seatbelt.BuildProfile()
	if err != seatbelt.ErrNoRules {
		t.Fatalf("expected ErrNoRules, got: %v", err)
	}
}

func TestBuildProfile_AutoMinimal(t *testing.T) {
	// When no Import("bsd.sb") is provided, Minimal is auto-included.
	profile, err := seatbelt.BuildProfile(seatbelt.DenyNetwork())
	if err != nil {
		t.Fatal(err)
	}
	s := profile.String()
	if !strings.Contains(s, `(import "bsd.sb")`) {
		t.Fatal("expected bsd.sb import from auto-Minimal")
	}
	if !strings.Contains(s, "(allow process-fork)") {
		t.Fatal("expected process-fork from auto-Minimal")
	}
}

func TestBuildProfile_WithoutMinimal(t *testing.T) {
	profile, err := seatbelt.BuildProfile(
		seatbelt.WithoutMinimal(),
		seatbelt.Import("bsd.sb"),
		seatbelt.AllowFork(),
	)
	if err != nil {
		t.Fatal(err)
	}
	s := profile.String()
	// Should have bsd.sb but NOT the full Minimal set.
	if !strings.Contains(s, `(import "bsd.sb")`) {
		t.Fatal("expected bsd.sb import")
	}
	if strings.Contains(s, "com.apple.trustd.agent") {
		t.Fatal("should not have trustd.agent without Minimal")
	}
}

func TestBuildProfile_DuplicateImports(t *testing.T) {
	profile, err := seatbelt.BuildProfile(
		seatbelt.Import("bsd.sb"),
		seatbelt.Import("bsd.sb"),
		seatbelt.AllowFork(),
	)
	if err != nil {
		t.Fatal(err)
	}
	s := profile.String()
	count := strings.Count(s, `(import "bsd.sb")`)
	if count != 1 {
		t.Fatalf("expected exactly 1 bsd.sb import, got %d", count)
	}
}

func TestBuildProfile_ReadOnly(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only")
	}
	profile, err := seatbelt.BuildProfile(
		seatbelt.WithoutMinimal(),
		seatbelt.Import("bsd.sb"),
		seatbelt.ReadOnly("/etc"),
	)
	if err != nil {
		t.Fatal(err)
	}
	s := profile.String()
	if !strings.Contains(s, "file-read*") {
		t.Fatal("expected file-read* in profile")
	}
	if !strings.Contains(s, "file-read-metadata") {
		t.Fatal("expected file-read-metadata in profile")
	}
	// /etc -> /private/etc on macOS
	if !strings.Contains(s, "/private/etc") && !strings.Contains(s, `"/etc"`) {
		t.Fatal("expected /etc path in profile")
	}
}

func TestBuildProfile_ReadWrite(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only")
	}
	tmpDir, _ := os.MkdirTemp("", "seatbelt-build-*")
	defer os.RemoveAll(tmpDir)

	profile, err := seatbelt.BuildProfile(
		seatbelt.WithoutMinimal(),
		seatbelt.Import("bsd.sb"),
		seatbelt.ReadWrite(tmpDir),
	)
	if err != nil {
		t.Fatal(err)
	}
	s := profile.String()
	if !strings.Contains(s, "file-read*") {
		t.Fatal("expected file-read* in profile")
	}
	if !strings.Contains(s, "file-write*") {
		t.Fatal("expected file-write* in profile")
	}
}

func TestBuildProfile_Custom(t *testing.T) {
	profile, err := seatbelt.BuildProfile(
		seatbelt.WithoutMinimal(),
		seatbelt.Import("bsd.sb"),
		seatbelt.Custom(`(allow file-read* (literal "/custom/path"))`),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(profile.String(), "/custom/path") {
		t.Fatal("expected custom SBPL in profile")
	}
}

func TestBuildProfile_DenyNetworkNoop(t *testing.T) {
	profile, err := seatbelt.BuildProfile(
		seatbelt.WithoutMinimal(),
		seatbelt.Import("bsd.sb"),
		seatbelt.DenyNetwork(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(profile.String(), "network") {
		t.Fatal("DenyNetwork should not produce any network SBPL")
	}
}

func TestBuildProfile_Presets(t *testing.T) {
	// Verify presets compose with additional rules.
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only")
	}
	tmpDir, _ := os.MkdirTemp("", "seatbelt-preset-*")
	defer os.RemoveAll(tmpDir)

	profile, err := seatbelt.BuildProfile(
		seatbelt.NoNetwork,
		seatbelt.ReadWrite(tmpDir),
	)
	if err != nil {
		t.Fatal(err)
	}
	s := profile.String()
	if !strings.Contains(s, `(import "bsd.sb")`) {
		t.Fatal("expected bsd.sb from NoNetwork preset")
	}
	if strings.Contains(s, "(allow network") {
		t.Fatal("NoNetwork should not allow any network operations")
	}
}

// ═══════════════════════════════════════════════════════════════════════
// FILE SYSTEM TESTS (via sandbox-exec)
// ═══════════════════════════════════════════════════════════════════════

func TestFS_ReadAllowedPath(t *testing.T) {
	r := runWithRules(t, []seatbelt.Rule{seatbelt.ReadOnly("/etc")},
		"fs-read-file", "/etc/hosts")
	expectSuccess(t, r)
}

func TestFS_ReadDeniedPath(t *testing.T) {
	r := runWithRules(t, []seatbelt.Rule{seatbelt.ReadOnly("/etc")},
		"fs-read-file", "/var/log/system.log")
	expectDenied(t, r)
}

func TestFS_WriteToReadOnlyPath(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "seatbelt-ro-*")
	defer os.RemoveAll(tmpDir)

	r := runWithRules(t, []seatbelt.Rule{seatbelt.ReadOnly(tmpDir)},
		"fs-write-file", filepath.Join(tmpDir, "blocked.txt"))
	expectDenied(t, r)
}

func TestFS_WriteToReadWritePath(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "seatbelt-rw-*")
	defer os.RemoveAll(tmpDir)

	r := runWithRules(t, []seatbelt.Rule{seatbelt.ReadWrite(tmpDir)},
		"fs-write-file", filepath.Join(tmpDir, "allowed.txt"))
	expectSuccess(t, r)
}

func TestFS_WriteToUnmentionedPath(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "seatbelt-allowed-*")
	defer os.RemoveAll(tmpDir)
	otherDir, _ := os.MkdirTemp("", "seatbelt-denied-*")
	defer os.RemoveAll(otherDir)

	r := runWithRules(t, []seatbelt.Rule{seatbelt.ReadWrite(tmpDir)},
		"fs-write-file", filepath.Join(otherDir, "blocked.txt"))
	expectDenied(t, r)
}

func TestFS_MkdirDenied(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "seatbelt-mkdir-*")
	defer os.RemoveAll(tmpDir)

	r := runWithRules(t, []seatbelt.Rule{seatbelt.ReadOnly(tmpDir)},
		"fs-mkdir", filepath.Join(tmpDir, "newdir"))
	expectDenied(t, r)
}

func TestFS_MkdirAllowed(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "seatbelt-mkdir-*")
	defer os.RemoveAll(tmpDir)

	r := runWithRules(t, []seatbelt.Rule{seatbelt.ReadWrite(tmpDir)},
		"fs-mkdir", filepath.Join(tmpDir, "newdir"))
	expectSuccess(t, r)
}

func TestFS_RemoveDenied(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "seatbelt-rm-*")
	defer os.RemoveAll(tmpDir)
	os.WriteFile(filepath.Join(tmpDir, "victim.txt"), []byte("data"), 0644)

	r := runWithRules(t, []seatbelt.Rule{seatbelt.ReadOnly(tmpDir)},
		"fs-remove", filepath.Join(tmpDir, "victim.txt"))
	expectDenied(t, r)
}

func TestFS_StatAllowed(t *testing.T) {
	r := runWithRules(t, []seatbelt.Rule{seatbelt.ReadOnly("/etc")},
		"fs-stat", "/etc/hosts")
	expectSuccess(t, r)
}

func TestFS_StatAllowedByBsdSb(t *testing.T) {
	// bsd.sb grants file-read-metadata broadly.
	tmpDir, _ := os.MkdirTemp("", "seatbelt-stat-bsd-*")
	defer os.RemoveAll(tmpDir)
	os.WriteFile(filepath.Join(tmpDir, "test.txt"), []byte("data"), 0644)

	r := runWithRules(t, nil, "fs-stat", filepath.Join(tmpDir, "test.txt"))
	expectSuccess(t, r)
}

func TestFS_ReadDataDenied(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "seatbelt-readdata-denied-*")
	defer os.RemoveAll(tmpDir)
	os.WriteFile(filepath.Join(tmpDir, "secret.txt"), []byte("data"), 0644)

	r := runWithRules(t, nil, "fs-read-file", filepath.Join(tmpDir, "secret.txt"))
	expectDenied(t, r)
}

func TestFS_RenameAllowed(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "seatbelt-rename-*")
	defer os.RemoveAll(tmpDir)
	os.WriteFile(filepath.Join(tmpDir, "a.txt"), []byte("data"), 0644)

	r := runWithRules(t, []seatbelt.Rule{seatbelt.ReadWrite(tmpDir)},
		"fs-rename", filepath.Join(tmpDir, "a.txt"), filepath.Join(tmpDir, "b.txt"))
	expectSuccess(t, r)
}

func TestFS_RenameDenied(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "seatbelt-rename-*")
	defer os.RemoveAll(tmpDir)
	os.WriteFile(filepath.Join(tmpDir, "a.txt"), []byte("data"), 0644)

	r := runWithRules(t, []seatbelt.Rule{seatbelt.ReadOnly(tmpDir)},
		"fs-rename", filepath.Join(tmpDir, "a.txt"), filepath.Join(tmpDir, "b.txt"))
	expectDenied(t, r)
}

func TestFS_SymlinkTraversal(t *testing.T) {
	tmpFile, _ := os.CreateTemp("/tmp", "seatbelt-symlink-*")
	tmpFile.Write([]byte("hello"))
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	r := runWithRules(t, []seatbelt.Rule{seatbelt.ReadOnly("/tmp")},
		"fs-read-file", tmpFile.Name())
	expectSuccess(t, r)
}

func TestFS_HardlinkEscape(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "seatbelt-hardlink-*")
	defer os.RemoveAll(tmpDir)

	r := runWithRules(t, []seatbelt.Rule{seatbelt.ReadWrite(tmpDir)},
		"fs-hardlink", "/etc/hosts", filepath.Join(tmpDir, "hosts-link"))
	expectDenied(t, r)
}

func TestFS_WriteOnlyCanWrite(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "seatbelt-wo-*")
	defer os.RemoveAll(tmpDir)

	r := runWithRules(t, []seatbelt.Rule{seatbelt.WriteOnly(tmpDir)},
		"fs-write-only-write", filepath.Join(tmpDir, "wo.txt"))
	expectSuccess(t, r)
}

func TestFS_WriteOnlyCannotRead(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "seatbelt-wo-*")
	defer os.RemoveAll(tmpDir)
	os.WriteFile(filepath.Join(tmpDir, "wo.txt"), []byte("secret"), 0644)

	r := runWithRules(t, []seatbelt.Rule{seatbelt.WriteOnly(tmpDir)},
		"fs-write-only-read", filepath.Join(tmpDir, "wo.txt"))
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

	r := runWithRules(t, []seatbelt.Rule{seatbelt.ReadOnly(subDir)},
		"fs-read-file", filepath.Join(siblingDir, "secret.txt"))
	expectDenied(t, r)
}

func TestFS_ReadDir(t *testing.T) {
	r := runWithRules(t, []seatbelt.Rule{seatbelt.ReadOnly("/etc")},
		"fs-readdir", "/etc")
	expectSuccess(t, r)
}

func TestFS_ReadDirDenied(t *testing.T) {
	r := runWithRules(t, nil, "fs-readdir", "/etc")
	expectDenied(t, r)
}

// ═══════════════════════════════════════════════════════════════════════
// NETWORK TESTS
// ═══════════════════════════════════════════════════════════════════════

func TestNet_DeniedByDefault(t *testing.T) {
	r := runWithRules(t, nil, "net-dial-tcp", "1.1.1.1:80")
	expectDenied(t, r)
}

func TestNet_OutboundAllowed(t *testing.T) {
	r := runWithRules(t, []seatbelt.Rule{
		seatbelt.AllowNetworkOutbound(),
		seatbelt.ReadOnly("/etc", "/private/var/run"),
	}, "net-dial-tcp", "1.1.1.1:80")
	expectSuccess(t, r)
}

func TestNet_InboundDeniedWhenOutboundOnly(t *testing.T) {
	r := runWithRules(t, []seatbelt.Rule{seatbelt.AllowNetworkOutbound()},
		"net-listen-tcp")
	expectDenied(t, r)
}

func TestNet_InboundAllowed(t *testing.T) {
	r := runWithRules(t, []seatbelt.Rule{
		seatbelt.AllowNetworkInbound(),
		seatbelt.AllowNetworkOutbound(),
	}, "net-listen-tcp")
	expectSuccess(t, r)
}

func TestNet_FullNetworkAllowed(t *testing.T) {
	rules := []seatbelt.Rule{
		seatbelt.AllowNetwork(),
		seatbelt.ReadOnly("/etc", "/private/var/run"),
	}
	r := runWithRules(t, rules, "net-dial-tcp", "1.1.1.1:80")
	expectSuccess(t, r)
	r = runWithRules(t, rules, "net-listen-tcp")
	expectSuccess(t, r)
}

func TestNet_UDPDenied(t *testing.T) {
	r := runWithRules(t, nil, "net-dial-udp", "8.8.8.8:53")
	expectDenied(t, r)
}

func TestNet_UDPAllowedWithFullNetwork(t *testing.T) {
	r := runWithRules(t, []seatbelt.Rule{seatbelt.AllowNetwork()},
		"net-dial-udp", "8.8.8.8:53")
	expectSuccess(t, r)
}

func TestNet_LocalhostDenied(t *testing.T) {
	r := runWithRules(t, nil, "net-localhost", "12345")
	expectDenied(t, r)
}

func TestNet_HTTPGetDenied(t *testing.T) {
	r := runWithRules(t, nil, "net-http-get", "http://example.com")
	expectDenied(t, r)
}

// ═══════════════════════════════════════════════════════════════════════
// PROCESS EXECUTION TESTS
// ═══════════════════════════════════════════════════════════════════════

func TestProc_ExecAllowedBinary(t *testing.T) {
	r := runWithRules(t, []seatbelt.Rule{
		seatbelt.AllowExec("/bin/echo"),
		seatbelt.ReadOnly("/bin", "/usr/lib"),
	}, "proc-exec", "/bin/echo", "hello")
	expectSuccess(t, r)
	if !strings.Contains(r.Data, "hello") {
		t.Fatalf("expected 'hello', got: %s", r.Data)
	}
}

func TestProc_ExecDeniedBinary(t *testing.T) {
	r := runWithRules(t, []seatbelt.Rule{
		seatbelt.AllowExec("/bin/echo"),
		seatbelt.ReadOnly("/usr"),
	}, "proc-exec", "/usr/bin/id")
	expectDenied(t, r)
}

func TestProc_ExecNoRules(t *testing.T) {
	r := runWithRules(t, nil, "proc-exec", "/bin/echo", "nope")
	expectDenied(t, r)
}

func TestProc_ExecDirectoryAllowsAllInDir(t *testing.T) {
	r := runWithRules(t, []seatbelt.Rule{
		seatbelt.AllowExec("/usr/bin"),
		seatbelt.ReadOnly("/usr"),
	}, "proc-exec", "/usr/bin/env")
	expectSuccess(t, r)
}

func TestProc_ShellEscapeAttempt(t *testing.T) {
	r := runWithRules(t, []seatbelt.Rule{
		seatbelt.AllowExec("/bin/sh"),
		seatbelt.ReadOnly("/bin", "/usr/lib", "/etc"),
	}, "proc-exec-shell-escape", "cat /etc/shadow")
	expectDenied(t, r)
}

func TestProc_ExecWrittenScript(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "seatbelt-script-*")
	defer os.RemoveAll(tmpDir)

	r := runWithRules(t, []seatbelt.Rule{
		seatbelt.ReadWrite(tmpDir),
		// Deliberately NOT allowing exec for tmpDir
	}, "proc-exec-written-script", tmpDir)
	expectDenied(t, r)
}

// ═══════════════════════════════════════════════════════════════════════
// MACH IPC TESTS
// ═══════════════════════════════════════════════════════════════════════

func TestMach_TLSWithTrustd(t *testing.T) {
	if testing.Short() {
		t.Skip("TLS handshake test requires network access")
	}
	r := runWithRules(t, []seatbelt.Rule{
		seatbelt.AllowNetwork(),
		seatbelt.ReadOnly("/etc", "/private/var/run"),
	}, "mach-tls-handshake")
	expectSuccess(t, r)
}

// ═══════════════════════════════════════════════════════════════════════
// SYSCTL TESTS
// ═══════════════════════════════════════════════════════════════════════

func TestSysctl_ReadAllowed(t *testing.T) {
	r := runWithRules(t, nil, "sysctl-read", "kern.ostype")
	expectSuccess(t, r)
	if r.Data != "Darwin" {
		t.Fatalf("expected kern.ostype=Darwin, got: %s", r.Data)
	}
}

func TestSysctl_ReadProvidedByBsdSb(t *testing.T) {
	// bsd.sb grants sysctl-read implicitly — documented behavior.
	r := runWithRules(t, nil, "sysctl-read", "kern.ostype")
	expectSuccess(t, r)
}

// ═══════════════════════════════════════════════════════════════════════
// SIGNAL TESTS
// ═══════════════════════════════════════════════════════════════════════

func TestSignal_SelfAllowed(t *testing.T) {
	r := runWithRules(t, nil, "signal-self")
	expectSuccess(t, r)
}

func TestSignal_OtherProcess(t *testing.T) {
	r := runWithRules(t, nil, "signal-other")
	expectDenied(t, r)
}

// ═══════════════════════════════════════════════════════════════════════
// ESCAPE VECTOR TESTS
// ═══════════════════════════════════════════════════════════════════════

func TestEscape_SymlinkPivot(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "seatbelt-escape-symlink-*")
	defer os.RemoveAll(tmpDir)

	r := runWithRules(t, []seatbelt.Rule{seatbelt.ReadWrite(tmpDir)},
		"escape-symlink-pivot", tmpDir, "/var/log/system.log")
	expectDenied(t, r)
}

func TestEscape_RenameToRestrictedPath(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "seatbelt-escape-rename-*")
	defer os.RemoveAll(tmpDir)
	targetDir, _ := os.MkdirTemp("", "seatbelt-escape-target-*")
	defer os.RemoveAll(targetDir)

	r := runWithRules(t, []seatbelt.Rule{seatbelt.ReadWrite(tmpDir)},
		"escape-rename-to-denied",
		filepath.Join(tmpDir, "src.txt"), filepath.Join(targetDir, "dst.txt"))
	expectDenied(t, r)
}

func TestEscape_Chroot(t *testing.T) {
	r := runWithRules(t, nil, "escape-chroot")
	expectDenied(t, r)
}

func TestEscape_Ptrace(t *testing.T) {
	r := runWithRules(t, nil, "escape-ptrace")
	expectDenied(t, r)
}

func TestEscape_AppleScript(t *testing.T) {
	r := runWithRules(t, nil, "escape-applescript")
	expectDenied(t, r)
}

func TestEscape_Keychain(t *testing.T) {
	r := runWithRules(t, nil, "escape-keychain")
	expectDenied(t, r)
}

func TestEscape_MmapDeniedFile(t *testing.T) {
	r := runWithRules(t, nil, "escape-mmap-denied", "/etc/hosts")
	expectDenied(t, r)
}

func TestEscape_EnvExfiltration(t *testing.T) {
	r := runWithRules(t, nil, "escape-env-exfil")
	expectSuccess(t, r)
	if !strings.Contains(r.Data, "marker=1") {
		t.Fatalf("expected _SEATBELT_CHILD=1 in env, got: %s", r.Data)
	}
}

func TestEscape_DevFd(t *testing.T) {
	r := runWithRules(t, []seatbelt.Rule{seatbelt.ReadOnly("/dev")},
		"escape-dev-fd")
	expectSuccess(t, r)
}

func TestEscape_IPCShm(t *testing.T) {
	// Build a custom profile WITHOUT ipc-posix-sem to test IPC denial.
	profile := buildProfile(t,
		seatbelt.WithoutMinimal(),
		seatbelt.Import("bsd.sb"),
		seatbelt.AllowFork(),
		seatbelt.AllowSignal(),
		seatbelt.AllowSysctlRead(),
		seatbelt.AllowMachLookup("com.apple.trustd.agent"),
		// No AllowIPCPosixShm
	)
	r := runSandboxed(t, profile, "escape-ipc-shm")
	expectDenied(t, r)
}

// ═══════════════════════════════════════════════════════════════════════
// LIFECYCLE / RE-EXEC TESTS
// ═══════════════════════════════════════════════════════════════════════

func TestLifecycle_CleanExit(t *testing.T) {
	binary := buildHelper(t)
	profile := buildProfile(t)
	cmd := exec.Command("sandbox-exec", "-p", profile, binary, "exit-code", "0")
	cmd.Env = append(os.Environ(), "_SEATBELT_CHILD=1")
	if err := cmd.Run(); err != nil {
		t.Fatalf("expected clean exit, got: %v", err)
	}
}

func TestLifecycle_ErrorExit(t *testing.T) {
	binary := buildHelper(t)
	profile := buildProfile(t)
	cmd := exec.Command("sandbox-exec", "-p", profile, binary, "exit-code", "42")
	cmd.Env = append(os.Environ(), "_SEATBELT_CHILD=1")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit")
	}
	if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 42 {
		t.Fatalf("expected exit code 42, got: %v", err)
	}
}

func TestLifecycle_ArgsPreservation(t *testing.T) {
	r := runWithRules(t, nil, "print-args")
	expectSuccess(t, r)
	if !strings.Contains(r.Data, "print-args") {
		t.Fatalf("expected 'print-args' in args, got: %s", r.Data)
	}
}

func TestLifecycle_EnvPreservation(t *testing.T) {
	binary := buildHelper(t)
	profile := buildProfile(t)
	cmd := exec.Command("sandbox-exec", "-p", profile, binary, "print-env", "SEATBELT_TEST_VAR")
	cmd.Env = append(os.Environ(), "_SEATBELT_CHILD=1", "SEATBELT_TEST_VAR=hello_from_parent")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v\n%s", err, out)
	}
	var r helperResult
	json.Unmarshal(out, &r)
	if r.Data != "hello_from_parent" {
		t.Fatalf("expected 'hello_from_parent', got: %s", r.Data)
	}
}

func TestLifecycle_CWDPreservation(t *testing.T) {
	binary := buildHelper(t)
	profile := buildProfile(t, seatbelt.ReadOnly("/tmp"))
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
	r := runWithRules(t, nil, "is-sandboxed")
	expectSuccess(t, r)
	if r.Data != "1" {
		t.Fatalf("expected _SEATBELT_CHILD=1, got: %s", r.Data)
	}
}

func TestLifecycle_RuntimeInfo(t *testing.T) {
	r := runWithRules(t, nil, "print-runtime")
	expectSuccess(t, r)
	if !strings.Contains(r.Data, "os=darwin") {
		t.Fatalf("expected darwin, got: %s", r.Data)
	}
}

func TestLifecycle_IsSandboxedAPI(t *testing.T) {
	// In the test process (not sandboxed), IsSandboxed should be false.
	if seatbelt.IsSandboxed() {
		t.Fatal("IsSandboxed should return false in test process")
	}
	if seatbelt.SandboxProfile() != "" {
		t.Fatal("SandboxProfile should return empty in test process")
	}
}

func TestLifecycle_RestrictErrors(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only")
	}
	// Empty rules should error.
	_, err := seatbelt.Restrict()
	if err != seatbelt.ErrNoRules {
		t.Fatalf("expected ErrNoRules, got: %v", err)
	}
}

// ═══════════════════════════════════════════════════════════════════════
// CONCURRENCY / STRESS TESTS
// ═══════════════════════════════════════════════════════════════════════

func TestStress_ConcurrentReadAllowed(t *testing.T) {
	if testing.Short() {
		t.Skip("stress test")
	}
	r := runWithRules(t, []seatbelt.Rule{seatbelt.ReadOnly("/etc")},
		"concurrent-read", "/etc/hosts")
	expectSuccess(t, r)
}

func TestStress_ConcurrentDeniedAccess(t *testing.T) {
	if testing.Short() {
		t.Skip("stress test")
	}
	r := runWithRules(t, nil, "concurrent-denied", "/etc/hosts")
	expectSuccess(t, r)
	if !strings.Contains(r.Data, "100 denied") {
		t.Fatalf("expected all 100 denied, got: %s", r.Data)
	}
}

func TestStress_ManyOpenFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("stress test")
	}
	tmpDir, _ := os.MkdirTemp("", "seatbelt-stress-*")
	defer os.RemoveAll(tmpDir)

	r := runWithRules(t, []seatbelt.Rule{seatbelt.ReadWrite(tmpDir)},
		"fs-open-many", tmpDir)
	expectSuccess(t, r)
}

func TestStress_LargeFileIO(t *testing.T) {
	if testing.Short() {
		t.Skip("stress test")
	}
	tmpDir, _ := os.MkdirTemp("", "seatbelt-largefile-*")
	defer os.RemoveAll(tmpDir)

	r := runWithRules(t, []seatbelt.Rule{seatbelt.ReadWrite(tmpDir)},
		"fs-large-file", tmpDir)
	expectSuccess(t, r)
}

func TestStress_RapidReexec(t *testing.T) {
	if testing.Short() {
		t.Skip("stress test")
	}
	for i := 0; i < 10; i++ {
		r := runWithRules(t, nil, "noop")
		expectSuccess(t, r)
	}
}
