# Implementation Plan

Step-by-step plan for implementing the `github.com/mkke/seatbelt` library.

## Table of Contents

- [Phase 1: Core Types and SBPL Profile Builder](#phase-1-core-types-and-sbpl-profile-builder)
- [Phase 2: Re-execution Mechanism](#phase-2-re-execution-mechanism)
- [Phase 3: Presets and Ergonomics](#phase-3-presets-and-ergonomics)
- [Phase 4: Optional cgo Self-Sandbox Module](#phase-4-optional-cgo-self-sandbox-module)
- [Phase 5: go-daemon Integration](#phase-5-go-daemon-integration)
- [Phase 6: Test Suite](#phase-6-test-suite)

---

## Phase 1: Core Types and SBPL Profile Builder

Build the foundation: the `Rule` interface, concrete rule types, and the SBPL
code generator.

### Step 1.1: Define the Rule interface and core types

**File: `rule.go`**

```go
package seatbelt

// Rule represents a single sandbox allow-rule.
// Rules are combined to form a complete sandbox profile.
type Rule interface {
    // sbpl returns the SBPL fragment(s) for this rule.
    // Each fragment is a complete (allow ...) or (import ...) expression.
    sbpl() []string
}
```

Define concrete rule structs (unexported, exposed via constructors):

- `fileRule` — holds operation names (`file-read*`, `file-write*`, etc.) and
  a list of paths.  Each path is resolved and emitted as both `(subpath ...)`
  and `(literal ...)` depending on whether it's a directory or file.
- `processRule` — holds operation (`process-exec`, `process-fork`) and
  optional paths.
- `networkRule` — holds operation (`network*`, `network-outbound`,
  `network-inbound`).
- `machRule` — holds service names (literal) or prefix (regex).
- `sysctlRule` — holds operation (`sysctl-read`, `sysctl-write`).
- `signalRule` — no fields.
- `iokitRule` — no fields.
- `ipcRule` — holds IPC type (`ipc-posix-shm-*`, `ipc-posix-sem`).
- `importRule` — holds profile name string.
- `customRule` — holds raw SBPL string.
- `noopRule` — produces no SBPL output (used by `DenyNetwork()`).
- `presetRule` — wraps a `[]Rule` slice (used by preset profiles).

### Step 1.2: Implement rule constructors

**File: `rules.go`**

Implement all public constructors:

```go
func ReadOnly(paths ...string) Rule
func ReadWrite(paths ...string) Rule
func WriteOnly(paths ...string) Rule
func AllowExec(paths ...string) Rule
func AllowFork() Rule
func AllowSignal() Rule
func AllowNetwork() Rule
func AllowNetworkOutbound() Rule
func AllowNetworkInbound() Rule
func DenyNetwork() Rule
func AllowMachLookup(services ...string) Rule
func AllowMachLookupPrefix(prefix string) Rule
func AllowSysctlRead() Rule
func AllowIOKit() Rule
func AllowIPCPosixShm() Rule
func AllowIPCPosixSem() Rule
func Import(profile string) Rule
func Custom(sbpl string) Rule
```

Each constructor:
1. Validates inputs (non-empty paths, valid service names).
2. Returns the appropriate concrete rule struct.

### Step 1.3: Implement path resolution

**File: `path.go`**

```go
// resolvePaths takes a list of paths and returns deduplicated (original, resolved)
// pairs.  Symlinks are resolved via filepath.EvalSymlinks.  Both the original
// and resolved paths are needed because SBPL operates on resolved vnodes but
// users specify logical paths.
func resolvePaths(paths []string) ([]resolvedPath, error)

type resolvedPath struct {
    original string
    resolved string
    isDir    bool
}
```

Key behaviors:
- Resolve each path via `filepath.EvalSymlinks`.
- `os.Stat` to determine if directory or file.
- Deduplicate: if original == resolved, emit once.
- Return error for paths that don't exist (caller decides whether to ignore).

### Step 1.4: Implement SBPL generation

**File: `profile.go`**

```go
// Profile represents a complete sandbox profile ready for application.
type Profile struct {
    source string // the generated SBPL source
}

// BuildProfile compiles a set of rules into a complete SBPL profile string.
func BuildProfile(rules ...Rule) (*Profile, error)

// String returns the SBPL source.
func (p *Profile) String() string
```

`BuildProfile` implementation:
1. Start with `(version 1)\n(deny default)\n`.
2. Collect `sbpl()` fragments from all rules, deduplicating imports.
3. Order: imports first, then file rules, process rules, network rules,
   Mach rules, system rules, custom rules.
4. Join fragments with newlines.
5. Validate total length ≤ 65535 bytes; return error if exceeded.
6. Return `&Profile{source: joined}`.

### Step 1.5: Unit tests for profile generation

**File: `profile_test.go`**

Test cases:
- Empty rule set produces `(version 1)(deny default)` only.
- `ReadOnly("/tmp")` produces correct `file-read*` + `file-read-metadata` with
  both `/tmp` and `/private/tmp` paths.
- `ReadWrite` produces both read and write operations.
- `AllowExec` uses `(literal ...)` for files, `(subpath ...)` for directories.
- `AllowMachLookup` produces `(global-name "...")` literals.
- `AllowMachLookupPrefix` produces `(global-name-regex ...)`.
- `Import("bsd.sb")` appears before other rules.
- `Custom()` is emitted verbatim.
- `DenyNetwork()` produces no SBPL output.
- Profile exceeding 65535 bytes returns an error.
- Duplicate imports are deduplicated.
- Path resolution handles symlinks (mock via temp symlinks in tests).

---

## Phase 2: Re-execution Mechanism

Implement the `sandbox-exec`-based re-execution pattern.

### Step 2.1: Environment variable protocol

**File: `reexec.go`**

```go
const (
    envMarker  = "_SEATBELT_CHILD"
    envProfile = "_SEATBELT_PROFILE"
    markerVal  = "1"
)

// IsSandboxed reports whether the current process was re-executed
// inside a seatbelt sandbox.
func IsSandboxed() bool {
    return os.Getenv(envMarker) == markerVal
}

// SandboxProfile returns the SBPL profile source if sandboxed, or "".
func SandboxProfile() string {
    return os.Getenv(envProfile)
}
```

### Step 2.2: Locate sandbox-exec

**File: `sandbox_exec.go`**

```go
// findSandboxExec locates the sandbox-exec binary.
// Returns ErrSandboxExecNotFound if not available.
func findSandboxExec() (string, error)
```

Search order:
1. `/usr/bin/sandbox-exec` (standard location).
2. `exec.LookPath("sandbox-exec")` as fallback.
3. Return `ErrSandboxExecNotFound` with guidance.

Also check `runtime.GOOS == "darwin"`; return `ErrUnsupportedPlatform` otherwise.

### Step 2.3: Implement Restrict()

**File: `restrict.go`**

```go
// Restrict re-executes the current process under a seatbelt sandbox.
//
// Returns (*os.Process, nil) in the parent — the caller should wait on
// the child process.
// Returns (nil, nil) in the sandboxed child — the caller should proceed
// with application logic and call Release() when done.
// Returns (nil, error) on failure.
func Restrict(rules ...Rule) (*os.Process, error)
```

Implementation — parent path (when `!IsSandboxed()`):
1. Call `findSandboxExec()`.
2. Call `BuildProfile(rules...)` to generate SBPL.
3. Resolve the current executable via `os.Executable()`.
4. Build the command:
   ```
   sandbox-exec -p <sbpl> /path/to/self <original-args>
   ```
   If SBPL exceeds a safe arg length (~128KB), write to a temp file and use
   `-f` instead of `-p`.
5. Set up the child environment:
   - Copy `os.Environ()`.
   - Append `_SEATBELT_CHILD=1`.
   - Append `_SEATBELT_PROFILE=<sbpl>` (for introspection).
6. Set `cmd.Stdin`, `cmd.Stdout`, `cmd.Stderr` to the parent's fds.
7. Start the child process via `os.StartProcess` (not `exec.Command`, to match
   go-daemon's lower-level approach and avoid signal group issues).
8. Return `(child, nil)`.

Implementation — child path (when `IsSandboxed()`):
1. Return `(nil, nil)`.

### Step 2.4: Implement Release()

**File: `restrict.go`**

```go
// Release cleans up resources after the sandboxed process exits.
// Currently removes any temporary profile files.
func Release()
```

If a temp profile file was created (passed via another env var
`_SEATBELT_PROFILE_FILE`), delete it.

### Step 2.5: Handle edge cases

**File: `restrict.go` additions**

- **Double sandboxing guard:** If `IsSandboxed()` and `Restrict()` is called
  again, return `ErrAlreadySandboxed`.
- **argv preservation:** Pass `os.Args[1:]` to the child.  The child's
  `os.Args[0]` will be the executable path, not `sandbox-exec`.
- **Working directory:** Set `Attr.Dir` to the current working directory.
- **Signal forwarding:** In the parent, forward SIGINT, SIGTERM, SIGHUP to the
  child process so Ctrl-C works naturally.

### Step 2.6: Integration tests for re-execution

**File: `restrict_test.go`**

These tests compile a helper binary that calls `Restrict()`, then verify
behavior:

- Helper with `ReadOnly("/")` can read `/etc/hosts` but not write to `/tmp`.
- Helper with `DenyNetwork()` cannot make TCP connections.
- `IsSandboxed()` returns `false` in parent, `true` in child.
- Child inherits parent's stdout/stderr (verify by checking output).
- Child exit code is propagated correctly.
- Double `Restrict()` call returns `ErrAlreadySandboxed`.
- `os.Args` are preserved in child.
- Working directory is preserved.
- Environment variables (minus internal markers) are preserved.

---

## Phase 3: Presets and Ergonomics

### Step 3.1: Define preset profiles

**File: `preset.go`**

```go
// Preset is a pre-configured set of rules for common use cases.
// Presets implement Rule so they can be composed with other rules.
type Preset struct {
    rules []Rule
}

var (
    // Minimal provides the minimum rules for a Go process to run.
    Minimal = Preset{rules: []Rule{
        Import("bsd.sb"),
        AllowFork(),
        AllowSignal(),
        AllowSysctlRead(),
        AllowMachLookup(
            "com.apple.trustd.agent",
            "com.apple.SystemConfiguration.configd",
        ),
        AllowIPCPosixSem(),
    }}

    // NoNetwork extends Minimal: no network access, file system rules
    // must be added separately.
    NoNetwork = Preset{rules: append(Minimal.rules, DenyNetwork())}

    // NoWrite extends Minimal: read-only file system, no network.
    NoWrite = Preset{rules: append(Minimal.rules,
        DenyNetwork(),
        ReadOnly("/"),
    )}

    // PureComputation extends Minimal: no I/O beyond what bsd.sb requires.
    PureComputation = Preset{rules: Minimal.rules}
)
```

Make `Preset` implement `Rule` so it composes with other rules in `Restrict()`.

### Step 3.2: Auto-include Minimal

Modify `BuildProfile` to automatically prepend `Minimal` rules if no
`Import("bsd.sb")` is present in the provided rules.  This prevents users from
accidentally creating profiles that crash on startup.

Provide `WithoutMinimal()` option for advanced users who want full control.

### Step 3.3: Errors and sentinel values

**File: `errors.go`**

```go
var (
    ErrUnsupportedPlatform  = errors.New("seatbelt: macOS required")
    ErrSandboxExecNotFound  = errors.New("seatbelt: sandbox-exec not found")
    ErrAlreadySandboxed     = errors.New("seatbelt: process is already sandboxed")
    ErrProfileTooLarge      = errors.New("seatbelt: profile exceeds 65535 byte limit")
    ErrNoRules              = errors.New("seatbelt: at least one rule is required")
)
```

---

## Phase 4: Optional cgo Self-Sandbox Module

### Step 4.1: cgo bindings

**File: `cgo/sandbox.go`**

```go
package cgo

// #cgo LDFLAGS: -lsystem_sandbox
//
// #include <stdlib.h>
//
// extern int sandbox_init(const char *profile, uint64_t flags, char **errorbuf);
// extern int sandbox_init_with_parameters(const char *profile, uint64_t flags,
//     const char *const parameters[], char **errorbuf);
// extern void sandbox_free_error(char *errorbuf);
// extern int sandbox_check(int pid, const char *operation, int type, ...);
import "C"

// Apply sandboxes the current process in-place using sandbox_init.
// The profile is compiled from the given rules.
// Once applied, the sandbox cannot be removed.
func Apply(rules ...seatbelt.Rule) error

// ApplyWithParams sandboxes the current process with parameterized SBPL.
// Parameters are key-value pairs accessible via (param "KEY") in custom SBPL.
func ApplyWithParams(params map[string]string, rules ...seatbelt.Rule) error

// Check tests whether an operation would be allowed for the given PID.
func Check(pid int, operation string) (bool, error)
```

Implementation of `Apply`:
1. Call `seatbelt.BuildProfile(rules...)` to get SBPL source.
2. Convert to C string.
3. Call `C.sandbox_init(cProfile, 0, &errBuf)`.
4. If return != 0, convert `errBuf` to Go string, free it, return error.

Implementation of `Check`:
1. Call `C.sandbox_check(C.int(pid), cOp, C.SANDBOX_FILTER_NONE)`.
2. Return `result == 0` (0 = allowed).

### Step 4.2: Build tags

**File: `cgo/sandbox.go`** — add build constraint:
```go
//go:build darwin && cgo
```

**File: `cgo/sandbox_stub.go`** — stub for non-darwin / non-cgo:
```go
//go:build !darwin || !cgo

package cgo

func Apply(rules ...seatbelt.Rule) error { return seatbelt.ErrUnsupportedPlatform }
func Check(pid int, operation string) (bool, error) { return false, seatbelt.ErrUnsupportedPlatform }
```

### Step 4.3: cgo unit tests

**File: `cgo/sandbox_test.go`**

- `Apply` with `PureComputation` succeeds (process continues running).
- After `Apply`, file operations outside allowed paths fail with EPERM.
- `Check` returns correct results for allowed and denied operations.
- Double `Apply` returns an error (sandbox cannot be re-initialized).
- `Apply` with invalid SBPL returns a descriptive error.

---

## Phase 5: go-daemon Integration

### Step 5.1: Document the integration pattern

**File: `doc.go`**

Package-level documentation showing the two-stage pattern:
```go
// Stage 1: Daemonize with go-daemon
// Stage 2: Sandbox with seatbelt
```

### Step 5.2: Verify environment variable compatibility

Write integration tests that confirm:
- `_GO_DAEMON=1` survives the seatbelt re-exec (it's in the environment, and
  seatbelt copies the full environment).
- `_SEATBELT_CHILD=1` survives the go-daemon re-exec (same reason).
- Both `daemon.WasReborn()` and `seatbelt.IsSandboxed()` return correct values
  in the final (doubly re-execed) process.

### Step 5.3: Test with actual go-daemon

**File: `integration/daemon_test.go`**

Build a test binary that:
1. Calls `daemon.Context.Reborn()`.
2. In the daemon child, calls `seatbelt.Restrict()`.
3. In the sandboxed daemon, writes a marker file to a permitted path.
4. Test verifies the marker file exists and was written by the sandboxed daemon.
5. Test verifies the sandboxed daemon cannot write outside permitted paths.

This test requires `go-daemon` as a test dependency only.

### Step 5.4: RestrictWithDaemon convenience function (optional)

Consider whether a combined function is worth the coupling:

```go
// RestrictDaemon daemonizes and sandboxes in one call.
// Equivalent to calling daemon.Reborn() then seatbelt.Restrict().
func RestrictDaemon(daemonCtx *daemon.Context, rules ...Rule) (*os.Process, error)
```

Decision: **defer to Phase 6 evaluation**.  The two-call pattern documented in
the README is clean enough.  A combined function adds a hard dependency on
go-daemon.

---

## Phase 6: Test Suite

### Step 6.1: Test infrastructure

**File: `testutil_test.go`**

Build a test helper framework:

```go
// sandboxedTest compiles and runs a Go test binary under a sandbox with
// the given rules.  Returns stdout, stderr, and exit code.
func sandboxedTest(t *testing.T, rules []Rule, testFunc string) (
    stdout, stderr string, exitCode int)
```

This works by:
1. Building a test helper binary from `testdata/sandbox_helper.go`.
2. Running it via `sandbox-exec` with the generated profile.
3. The helper binary calls a named test function and reports results.

The helper binary approach is necessary because `sandbox-exec` wraps a command
— we cannot sandbox the test process itself without re-executing.

**File: `testdata/sandbox_helper/main.go`**

A helper binary with registered test functions that exercise specific
operations.  It accepts a test name via command-line argument and runs the
corresponding function, printing results as JSON.

### Step 6.2: File system restriction tests

**File: `sandbox_fs_test.go`**

| # | Test | Rules | Operation | Expected |
|---|------|-------|-----------|----------|
| 1 | Read allowed path | `ReadOnly("/etc")` | `os.ReadFile("/etc/hosts")` | Success |
| 2 | Read denied path | `ReadOnly("/etc")` | `os.ReadFile("/Users/x/secret")` | EPERM |
| 3 | Write to read-only path | `ReadOnly("/tmp")` | `os.WriteFile("/tmp/x", ...)` | EPERM |
| 4 | Write to read-write path | `ReadWrite("/tmp")` | `os.WriteFile("/tmp/x", ...)` | Success |
| 5 | Write to unmentioned path | `ReadWrite("/tmp")` | `os.WriteFile("/var/x", ...)` | EPERM |
| 6 | Create directory denied | `ReadOnly("/tmp")` | `os.Mkdir("/tmp/newdir", ...)` | EPERM |
| 7 | Create directory allowed | `ReadWrite("/tmp")` | `os.Mkdir("/tmp/newdir", ...)` | Success |
| 8 | Delete file denied | `ReadOnly("/tmp")` | `os.Remove("/tmp/existing")` | EPERM |
| 9 | Symlink traversal | `ReadOnly("/tmp")` | Read via `/tmp` (symlink to `/private/tmp`) | Success (both paths allowed) |
| 10 | Symlink escape | `ReadOnly("/tmp")` | Create symlink from `/tmp/escape` → `/etc/passwd`, read it | EPERM on the target |
| 11 | Read file metadata | `ReadOnly("/etc")` | `os.Stat("/etc/hosts")` | Success |
| 12 | Read denied metadata | *(no file rules)* | `os.Stat("/etc/hosts")` | EPERM |
| 13 | Rename denied | `ReadOnly("/tmp")` | `os.Rename("/tmp/a", "/tmp/b")` | EPERM |
| 14 | Rename allowed | `ReadWrite("/tmp")` | `os.Rename("/tmp/a", "/tmp/b")` | Success |
| 15 | Hardlink escape | `ReadWrite("/tmp")` | `os.Link("/etc/passwd", "/tmp/link")` | EPERM (cannot read source) |
| 16 | Write-only can write | `WriteOnly("/tmp")` | `os.WriteFile("/tmp/x", ...)` | Success |
| 17 | Write-only cannot read | `WriteOnly("/tmp")` | `os.ReadFile("/tmp/x")` | EPERM |
| 18 | Deeply nested path | `ReadOnly("/a/b/c/d/e")` | Read file at that depth | Success |
| 19 | Parent of allowed not accessible | `ReadOnly("/a/b/c")` | `os.ReadFile("/a/b/other")` | EPERM |
| 20 | Glob of restricted dir | `ReadWrite("/tmp")` | `filepath.Glob("/etc/*")` | EPERM or empty |

### Step 6.3: Network restriction tests

**File: `sandbox_net_test.go`**

| # | Test | Rules | Operation | Expected |
|---|------|-------|-----------|----------|
| 1 | Network denied by default | `Minimal` only | `net.Dial("tcp", "1.1.1.1:80")` | EPERM |
| 2 | Outbound allowed | `AllowNetworkOutbound()` | `net.Dial("tcp", "1.1.1.1:80")` | Success |
| 3 | Inbound denied when outbound-only | `AllowNetworkOutbound()` | `net.Listen("tcp", ":0")` | EPERM |
| 4 | Inbound allowed | `AllowNetworkInbound()` | `net.Listen("tcp", ":0")` | Success |
| 5 | Full network allowed | `AllowNetwork()` | Both dial and listen | Success |
| 6 | UDP denied | `Minimal` only | `net.Dial("udp", "8.8.8.8:53")` | EPERM |
| 7 | UDP allowed with full network | `AllowNetwork()` | `net.Dial("udp", "8.8.8.8:53")` | Success |
| 8 | Unix socket denied | `Minimal` only | `net.Dial("unix", "/tmp/sock")` | EPERM |
| 9 | DNS resolution without network | `Minimal`, no network | `net.LookupHost("example.com")` | Fail (no UDP to DNS server) |
| 10 | HTTP request denied | `Minimal` only | `http.Get(...)` | Fail |
| 11 | HTTP request allowed | `AllowNetworkOutbound()` | `http.Get(...)` | Success |
| 12 | Localhost connection denied | `Minimal` only | `net.Dial("tcp", "127.0.0.1:X")` | EPERM |

### Step 6.4: Process execution tests

**File: `sandbox_process_test.go`**

| # | Test | Rules | Operation | Expected |
|---|------|-------|-----------|----------|
| 1 | Exec allowed binary | `AllowExec("/bin/echo")` | `exec.Command("/bin/echo", "hi")` | Success, output = "hi" |
| 2 | Exec denied binary | `AllowExec("/bin/echo")` | `exec.Command("/usr/bin/id")` | EPERM |
| 3 | Exec no rules | *(no exec rule)* | `exec.Command("/bin/echo", "hi")` | EPERM |
| 4 | Exec directory allows all in dir | `AllowExec("/usr/bin")` | `exec.Command("/usr/bin/env")` | Success |
| 5 | Exec via PATH | `AllowExec("/usr/bin")` | `exec.Command("env")` | Success (resolved to /usr/bin/env) |
| 6 | Exec via symlink | `AllowExec("/usr/bin/python3")` | exec via symlink path | Depends on resolution |
| 7 | Fork bomb (fork with no exec) | `AllowFork()` | Rapid `syscall.ForkExec` | Sandbox alone does not prevent; OS limits apply |
| 8 | Shell escape attempt | `AllowExec("/bin/sh")` | `/bin/sh -c 'cat /etc/shadow'` | `cat` exec denied (not in AllowExec) |
| 9 | Script execution | `AllowExec("/bin/sh")` | `/bin/sh script.sh` where script calls disallowed binary | Inner exec denied |

### Step 6.5: Mach IPC tests

**File: `sandbox_mach_test.go`**

| # | Test | Rules | Operation | Expected |
|---|------|-------|-----------|----------|
| 1 | Allowed Mach lookup | `AllowMachLookup("com.apple.trustd.agent")` | TLS handshake | Success |
| 2 | Denied Mach lookup | *(no Mach rules)* | TLS handshake | Fail |
| 3 | Prefix match | `AllowMachLookupPrefix("com.apple.")` | Multiple Apple services | Success |
| 4 | Prefix mismatch | `AllowMachLookupPrefix("com.apple.")` | Service `org.other.service` | Denied |
| 5 | DNS without configd | no `com.apple.SystemConfiguration.configd` | `net.LookupHost(...)` | Fail |
| 6 | DNS with configd | `AllowMachLookup("com.apple.SystemConfiguration.configd")` | `net.LookupHost(...)` | Success (with network) |

### Step 6.6: Sysctl and signal tests

**File: `sandbox_system_test.go`**

| # | Test | Rules | Operation | Expected |
|---|------|-------|-----------|----------|
| 1 | Sysctl read allowed | `AllowSysctlRead()` | `syscall.Sysctl("kern.ostype")` | Success |
| 2 | Sysctl read denied | *(no sysctl rule)* | `syscall.Sysctl("kern.ostype")` | EPERM |
| 3 | Signal self allowed | `AllowSignal()` | `syscall.Kill(os.Getpid(), 0)` | Success |
| 4 | Signal self denied | *(no signal rule)* | `syscall.Kill(os.Getpid(), 0)` | EPERM |
| 5 | Signal other process | `AllowSignal()` | `syscall.Kill(otherPid, SIGTERM)` | May succeed or deny depending on target |

### Step 6.7: Combined / escape vector tests

**File: `sandbox_escape_test.go`**

These tests attempt multi-step escape strategies:

| # | Test | Strategy | Expected |
|---|------|----------|----------|
| 1 | Symlink pivot | Create symlink in writable dir pointing to restricted path, access via symlink | Denied (kernel resolves vnodes) |
| 2 | /dev/fd escape | Open `/dev/fd/X` to access a pre-opened fd's path | Allowed (pre-opened fds survive; this is expected kernel behavior) |
| 3 | Temp file in allowed dir, move to denied | Write to `/tmp/file`, then `os.Rename` to `/etc/file` | Denied (rename target outside allowed paths) |
| 4 | Process substitution | Use named pipe in allowed dir as channel to unsandboxed process | Cannot create named pipe without exec of helper; exec denied |
| 5 | Environment variable exfiltration | Check that `_SEATBELT_PROFILE` is set but restricted paths in env don't leak | Profile is visible (by design) |
| 6 | Exec sandboxed child | Sandboxed process execs another binary; verify child inherits sandbox | Child is sandboxed (kernel inherits) |
| 7 | dlopen escape | Attempt to `dlopen` a library outside allowed paths | EPERM (file-read denied) |
| 8 | Memory-mapped file escape | `mmap` a file in denied path | EPERM (file-read denied before mmap) |
| 9 | Chroot escape | `syscall.Chroot(...)` inside sandbox | EPERM (not allowed) |
| 10 | Mount escape | Attempt to mount a filesystem | EPERM (not allowed) |
| 11 | ptrace attach | Attempt `PT_ATTACH` to parent process | EPERM |
| 12 | AppleScript escape | Attempt `osascript` to run unsandboxed command | EPERM (process-exec denied; appleevent-send denied) |
| 13 | Write then exec | Write a script to allowed path, exec it | EPERM if exec path not in AllowExec |
| 14 | Double sandbox (tighter) | Already sandboxed, apply tighter sandbox | Works (sandboxes stack; most restrictive wins) |
| 15 | Double sandbox (looser) | Already sandboxed, apply looser sandbox | New sandbox applies but can't expand beyond existing restrictions |
| 16 | IPC via Mach denied | Send Mach message to non-allowed service | Denied |
| 17 | IPC via POSIX shm denied | `shm_open` without `AllowIPCPosixShm()` | EPERM |
| 18 | Socket pair escape | Create socketpair, send fd over it to unsandboxed process | No unsandboxed process to receive (sandbox inherited) |
| 19 | Keychain access | Attempt to access macOS Keychain | Denied (Mach lookup to `com.apple.SecurityServer` denied) |
| 20 | Clipboard access | Attempt to access pasteboard | Denied (Mach lookup to `com.apple.pasteboard.pbs` denied) |

### Step 6.8: Re-execution lifecycle tests

**File: `sandbox_lifecycle_test.go`**

| # | Test | Scenario | Expected |
|---|------|----------|----------|
| 1 | Clean exit | Child exits 0 | Parent gets exit code 0 |
| 2 | Error exit | Child exits 1 | Parent gets exit code 1 |
| 3 | Signal death | Child killed by SIGTERM | Parent observes signal exit |
| 4 | Stdin forwarding | Parent pipes stdin to child | Child reads input |
| 5 | Stdout capture | Child writes to stdout | Parent captures output |
| 6 | Stderr capture | Child writes to stderr | Parent captures stderr |
| 7 | Args preservation | Parent passes `--flag value` | Child sees identical os.Args |
| 8 | Env preservation | Parent sets `MY_VAR=x` | Child sees `MY_VAR=x` |
| 9 | CWD preservation | Parent CWD is `/some/path` | Child CWD is `/some/path` |
| 10 | Signal forwarding | SIGINT sent to parent | Forwarded to child; child exits |
| 11 | Large profile | Profile near 65535 bytes | Works (via temp file) |
| 12 | Profile too large | Profile exceeds 65535 bytes | Returns ErrProfileTooLarge |
| 13 | IsSandboxed in parent | Before Restrict() | Returns false |
| 14 | IsSandboxed in child | After re-exec | Returns true |
| 15 | SandboxProfile in child | After re-exec | Returns the SBPL source |
| 16 | Release cleanup | After child exits | Temp files removed |
| 17 | Non-macOS platform | `runtime.GOOS != "darwin"` | Returns ErrUnsupportedPlatform |
| 18 | sandbox-exec missing | Binary not found | Returns ErrSandboxExecNotFound |

### Step 6.9: Preset tests

**File: `sandbox_preset_test.go`**

| # | Test | Preset | Verification |
|---|------|--------|-------------|
| 1 | Minimal boots | `Minimal` | Process starts, can read self, can read Go runtime paths |
| 2 | Minimal denies files | `Minimal` | Cannot read `/etc/hosts` (no file rules) |
| 3 | NoNetwork boots | `NoNetwork` + `ReadOnly("/")` | Process starts, can read files |
| 4 | NoNetwork denies net | `NoNetwork` | Cannot `net.Dial(...)` |
| 5 | NoWrite denies write | `NoWrite` | Cannot write anywhere |
| 6 | NoWrite allows read | `NoWrite` | Can read `/etc/hosts` |
| 7 | PureComputation boots | `PureComputation` | Process starts |
| 8 | PureComputation denies all I/O | `PureComputation` | Cannot read files, cannot use network |
| 9 | Preset + rules compose | `NoNetwork` + `ReadWrite("/tmp")` | Can write to /tmp, cannot use network |

### Step 6.10: Concurrency and stress tests

**File: `sandbox_stress_test.go`**

| # | Test | Scenario |
|---|------|----------|
| 1 | Concurrent file access | 100 goroutines read from allowed path simultaneously |
| 2 | Concurrent denied access | 100 goroutines attempt denied operations simultaneously |
| 3 | Rapid re-exec | Start and stop 10 sandboxed processes in sequence |
| 4 | Large file I/O in sandbox | Read/write a 100MB file in allowed path |
| 5 | Many open files | Open 1000 files in allowed path |

---

## Implementation Order

Recommended build order, each step producing a testable, shippable increment:

1. **Phase 1** (1.1–1.5): Rule types, SBPL generation, unit tests.
   *Deliverable: `BuildProfile()` works and is tested.*

2. **Phase 2** (2.1–2.6): Re-exec mechanism, integration tests.
   *Deliverable: `Restrict()` / `IsSandboxed()` work end-to-end.*

3. **Phase 3** (3.1–3.3): Presets, auto-Minimal, error types.
   *Deliverable: One-liner sandboxing with presets.*

4. **Phase 6.1–6.2**: File system restriction tests.
   *Deliverable: Confidence that file restrictions hold.*

5. **Phase 6.3–6.7**: Network, process, Mach, system, and escape tests.
   *Deliverable: Comprehensive breakout test coverage.*

6. **Phase 6.8–6.10**: Lifecycle, preset, and stress tests.
   *Deliverable: Production-grade test suite.*

7. **Phase 4** (4.1–4.3): Optional cgo module.
   *Deliverable: `cgo.Apply()` for advanced users.*

8. **Phase 5** (5.1–5.3): go-daemon integration tests.
   *Deliverable: Verified daemon + sandbox composition.*

Each phase is independently useful.  Phase 4 and 5 are optional extensions.
