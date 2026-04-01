# seatbelt

A Go library for declarative macOS sandbox (`seatbelt`) enforcement.

Provides a composable, allow-list API inspired by
[go-landlock](https://github.com/landlock-lsm/go-landlock/landlock)
and a re-execution model inspired by
[go-daemon](https://github.com/sevlyar/go-daemon) — tailored to the
capabilities of the macOS Seatbelt (App Sandbox / `sandbox_init`) subsystem.

```go
child, err := seatbelt.Restrict(
    seatbelt.ReadOnly("/usr", "/bin"),
    seatbelt.ReadWrite(workDir),
    seatbelt.AllowExec("/usr/bin/git"),
    seatbelt.DenyNetwork(),
)
if child != nil {
    os.Exit(waitForChild(child))
}
defer seatbelt.Release()
// everything below runs sandboxed
```

## Table of Contents

- [C API vs sandbox-exec — Research](#c-api-vs-sandbox-exec--research)
  - [The C API](#the-c-api)
  - [The sandbox-exec Tool](#the-sandbox-exec-tool)
  - [Comparison](#comparison)
  - [Recommendation](#recommendation)
- [Design](#design)
  - [Principles](#principles)
  - [Declarative Rule API](#declarative-rule-api)
  - [Re-execution Model](#re-execution-model)
  - [Combining with go-daemon](#combining-with-go-daemon)
  - [SBPL Profile Generation](#sbpl-profile-generation)
- [API Reference](#api-reference)
  - [Rules — File System](#rules--file-system)
  - [Rules — Process](#rules--process)
  - [Rules — Network](#rules--network)
  - [Rules — Mach IPC](#rules--mach-ipc)
  - [Rules — System](#rules--system)
  - [Rules — Composition](#rules--composition)
  - [Presets](#presets)
  - [Applying the Sandbox](#applying-the-sandbox)
- [Known Limitations and Gotchas](#known-limitations-and-gotchas)

---

## C API vs sandbox-exec — Research

macOS provides two mechanisms for applying a Seatbelt sandbox profile to a
process.  Both enforce the same kernel-level sandbox (the Seatbelt kext); they
differ in how the profile reaches the kernel.

### The C API

The public header `<sandbox.h>` (in the macOS SDK) declares two functions, both
deprecated since macOS 10.8:

```c
int  sandbox_init(const char *profile, uint64_t flags, char **errorbuf);
void sandbox_free_error(char *errorbuf);
```

`sandbox_init` sandboxes the **calling process**.  The `flags` argument selects
how `profile` is interpreted:

| Flag | Value | Meaning |
|------|-------|---------|
| `SANDBOX_NAMED` | `0x0001` | `profile` is one of five built-in names |
| *(undocumented)* `0x0000` | `0x0000` | `profile` is raw SBPL source |

Built-in profile names: `kSBXProfileNoInternet`, `kSBXProfileNoNetwork`,
`kSBXProfileNoWrite`, `kSBXProfileNoWriteExceptTemporary`,
`kSBXProfilePureComputation`.

**Private (undocumented) API** — available in `libsystem_sandbox.dylib` but
absent from public headers:

```c
int sandbox_init_with_parameters(const char *profile, uint64_t flags,
    const char *const parameters[], char **errorbuf);
int sandbox_check(pid_t pid, const char *operation,
    enum sandbox_filter_type type, ...);
char *sandbox_extension_issue_file(const char *extension_class,
    const char *path, uint32_t flags);
int64_t sandbox_extension_consume(const char *token);
int sandbox_extension_release(int64_t handle);
```

`sandbox_init_with_parameters` is the key function: it accepts a
NULL-terminated array of `{key, value}` pairs that are accessible in the SBPL
profile via `(param "KEY")`.  This is how Apple's own system services
parameterize their sandbox profiles.

`sandbox_extension_*` enables temporary access grants: a privileged process
issues an opaque token, and the sandboxed process consumes it to gain temporary
access to a specific file path.

Calling from Go requires **cgo**:

```go
// #cgo LDFLAGS: -lsystem_sandbox
// extern int sandbox_init_with_parameters(const char *profile,
//     uint64_t flags, const char *const parameters[], char **errorbuf);
// extern void sandbox_free_error(char *errorbuf);
import "C"
```

### The sandbox-exec Tool

`sandbox-exec` is a command-line wrapper (located at `/usr/bin/sandbox-exec`)
that takes a profile and a command, calls `sandbox_init` in itself, then
`execvp()`s the command:

```
sandbox-exec [-f profile_file] [-n profile_name] [-p profile_string]
             [-D key=value ...] command [arguments ...]
```

The sandbox is inherited by all child processes and cannot be removed.

- `-p` passes SBPL as a string argument
- `-f` reads SBPL from a file
- `-n` selects a built-in profile name
- `-D key=value` sets profile parameters (available as `(param "key")` in SBPL)

Both `sandbox-exec` and the C API are marked **deprecated**.  Both remain fully
functional on macOS 15 Sequoia and are relied upon in production by Bazel,
Nix, Homebrew, Anthropic (Claude Code), OpenAI (Codex), and others.

### Comparison

| Aspect | C API (`sandbox_init`) | `sandbox-exec` |
|--------|------------------------|----------------|
| **Target** | Self-sandbox (calling process) | Wraps another command |
| **cgo required** | Yes | No — pure Go via `os/exec` |
| **Self-sandboxing** | Direct | Must re-exec via `sandbox-exec /path/to/self` |
| **Child sandboxing** | Not directly (child must sandbox itself) | Direct — `sandbox-exec cmd args...` |
| **Parameters** | `const char *[]` array | `-D key=value` flags |
| **Extensions API** | Yes (`sandbox_extension_*`) | No |
| **Sandbox checking** | Yes (`sandbox_check`) | No |
| **Profile caching** | Possible (private `sandbox_compile`/`sandbox_apply`) | No (re-parsed each invocation) |
| **Profile size limit** | 65535 bytes serialized | Same (same kernel path) |
| **Cross-compilation** | Harder (cgo) | Trivial (pure Go) |
| **Timing** | Can sandbox at any point during execution | Sandbox is applied before `main()` |

### Recommendation

This library uses a **hybrid approach**:

1. **Primary mechanism — `sandbox-exec` for re-execution** (no cgo).
   The parent process re-executes itself via
   `sandbox-exec -p <profile> /path/to/self <args>` with a marker environment
   variable `_SEATBELT_CHILD=1`.  The child is sandboxed before any Go code
   runs.  This is the safest approach: there is no window between process start
   and sandbox application.

2. **Optional cgo module — `sandbox_init` for self-sandboxing**.
   Available via the `seatbelt/cgo` sub-package for callers who need to sandbox
   the current process in-place without re-execution, or who need access to the
   extensions API (`sandbox_extension_*`) or sandbox checking
   (`sandbox_check`).

The re-exec approach is recommended because:
- It requires no cgo, keeping builds simple and cross-compilation viable.
- The sandbox is active before `init()` functions run, closing the
  pre-sandbox window.
- It matches the go-daemon pattern users are already familiar with.
- `sandbox-exec` is the mechanism used by the most prominent sandbox
  implementations (Bazel, Claude Code, Codex).

---

## Design

### Principles

1. **Deny by default.**  Every generated profile starts with `(deny default)`.
   Rules are an allow-list: you declare what _is_ permitted.

2. **Declarative composition.**  Rules are values.  They compose via variadic
   arguments.  There are no mutable builders, no method chaining side effects.

3. **Symlink-aware.**  All paths are resolved via `filepath.EvalSymlinks` before
   being emitted as SBPL, because the macOS kernel sandbox operates on resolved
   (vnode-level) paths.  Both the original and resolved paths are included to
   handle edge cases.

4. **Presets for common policies.**  Batteries-included profiles
   (`Minimal`, `NoNetwork`, `NoWrite`, `PureComputation`) cover the most
   common use cases in a single call.

5. **Composable with go-daemon.**  The re-execution mechanism is designed to
   chain with `go-daemon`'s daemonization, enabling processes that are both
   daemonized _and_ sandboxed.

### Declarative Rule API

The API follows go-landlock's pattern: rule constructors return `Rule` values
that are passed to a single `Restrict()` call:

```go
child, err := seatbelt.Restrict(
    seatbelt.ReadOnly("/usr", "/bin", "/System"),
    seatbelt.ReadWrite("/tmp"),
    seatbelt.AllowExec("/usr/bin/env", "/bin/sh"),
    seatbelt.AllowNetwork(),
    seatbelt.AllowMachLookup("com.apple.trustd.agent"),
)
```

Each rule constructor maps to one or more SBPL operations:

| Constructor | SBPL operations |
|-------------|----------------|
| `ReadOnly(paths...)` | `file-read*`, `file-read-metadata` |
| `ReadWrite(paths...)` | `file-read*`, `file-write*`, `file-read-metadata` |
| `WriteOnly(paths...)` | `file-write*` |
| `AllowExec(paths...)` | `process-exec` |
| `AllowNetwork()` | `network*` |
| `AllowNetworkOutbound()` | `network-outbound` |
| `AllowMachLookup(names...)` | `mach-lookup` (literal match) |
| `AllowMachLookupPrefix(p)` | `mach-lookup` (regex match) |
| `AllowSysctlRead()` | `sysctl-read` |
| `AllowSignal()` | `signal` |
| `AllowFork()` | `process-fork` |
| `AllowIOKit()` | `iokit-open` |
| `Import(name)` | `(import "name.sb")` |
| `Custom(sbpl)` | raw SBPL fragment |

Rules that accept paths emit both `(subpath ...)` (for directories) and
`(literal ...)` (for files), with symlink resolution.

### Re-execution Model

Modeled after `go-daemon`'s `Context.Reborn()`:

```
                  ┌─────────────────┐
                  │  Original Process │
                  │  (unsandboxed)    │
                  └────────┬──────────┘
                           │ Restrict()
                           ▼
              ┌────────────────────────────┐
              │ sandbox-exec -p <profile>  │
              │   /path/to/self <args>     │
              │   env: _SEATBELT_CHILD=1   │
              └────────────┬───────────────┘
                           │
                  ┌────────▼──────────┐
                  │  Child Process    │
                  │  (sandboxed)      │
                  │  IsSandboxed()=T  │
                  └───────────────────┘
```

**Detection:** `IsSandboxed()` checks for the `_SEATBELT_CHILD=1` environment
variable, matching go-daemon's `WasReborn()` pattern.

**Profile transfer:** The SBPL profile is passed via `sandbox-exec -p` as a
command-line argument (for short profiles) or via `-f` pointing to a temporary
file (for profiles exceeding `ARG_MAX`).  The profile is also encoded in the
`_SEATBELT_PROFILE` environment variable so the child can inspect its own
restrictions.

**Lifecycle:**

```go
func main() {
    child, err := seatbelt.Restrict(rules...)
    if err != nil {
        log.Fatal(err)
    }
    if child != nil {
        // Parent: wait for sandboxed child
        state, _ := child.Wait()
        os.Exit(state.ExitCode())
    }
    defer seatbelt.Release()

    // Sandboxed code runs here
}
```

### Combining with go-daemon

The two re-execution patterns compose naturally.  Daemonization happens first
(detaching from the terminal), then sandboxing:

```go
func main() {
    // Stage 1: Daemonize
    daemonCtx := &daemon.Context{
        PidFileName: "/var/run/myapp.pid",
        LogFileName: "/var/log/myapp.log",
    }
    child, err := daemonCtx.Reborn()
    if err != nil {
        log.Fatal(err)
    }
    if child != nil {
        return // original parent exits
    }
    defer daemonCtx.Release()

    // Stage 2: Sandbox
    child, err = seatbelt.Restrict(
        seatbelt.ReadOnly("/usr", "/etc"),
        seatbelt.ReadWrite("/var/lib/myapp"),
        seatbelt.AllowExec("/usr/bin/git"),
        seatbelt.DenyNetwork(),
    )
    if err != nil {
        log.Fatal(err)
    }
    if child != nil {
        state, _ := child.Wait()
        os.Exit(state.ExitCode())
    }
    defer seatbelt.Release()

    // Running as daemon + sandboxed
    runServer()
}
```

The execution chain is:
1. **Original process** → spawns daemon via go-daemon → exits
2. **Daemon process** (`_GO_DAEMON=1`) → re-execs via seatbelt → waits
3. **Sandboxed daemon** (`_GO_DAEMON=1`, `_SEATBELT_CHILD=1`) → runs application

The order matters: daemonize first so the PID file, log file, and session
setup happen unsandboxed; then sandbox the final process.  The seatbelt
re-exec preserves the `_GO_DAEMON=1` environment variable, and go-daemon's
`WasReborn()` check passes in the final process.

### SBPL Profile Generation

Profiles are generated programmatically from the rule set.  A generated profile
looks like:

```scheme
(version 1)
(deny default)
(import "bsd.sb")

; File access
(allow file-read* file-read-metadata
    (subpath "/usr")
    (subpath "/bin"))
(allow file-read* file-write* file-read-metadata
    (subpath "/Users/me/project"))

; Process
(allow process-exec
    (literal "/usr/bin/git"))
(allow process-fork)
(allow signal)

; Mach IPC (required for Go runtime / DNS / TLS)
(allow mach-lookup
    (global-name "com.apple.trustd.agent")
    (global-name "com.apple.SystemConfiguration.configd"))

; System
(allow sysctl-read)
```

The `(import "bsd.sb")` line includes Apple's base system profile, which
provides the minimum operations a process needs to start (dyld, shared
libraries, system frameworks).  This is critical — without it, most processes
cannot even load.

The `Minimal` preset provides what a Go process needs beyond `bsd.sb`:
- Mach lookups for `com.apple.trustd.agent` (TLS certificate validation)
- Mach lookups for `com.apple.SystemConfiguration.configd` (DNS resolution)
- `sysctl-read` (Go runtime queries CPU count, page size, etc.)
- `process-fork` and `signal` (Go runtime)
- Read access to the executable itself and Go's temp directories

---

## API Reference

### Rules — File System

```go
// ReadOnly allows reading files and metadata under the given paths.
// Directories are matched recursively via (subpath ...).
func ReadOnly(paths ...string) Rule

// ReadWrite allows reading and writing files under the given paths.
func ReadWrite(paths ...string) Rule

// WriteOnly allows writing (but not reading) files under the given paths.
func WriteOnly(paths ...string) Rule
```

### Rules — Process

```go
// AllowExec permits executing the specified binaries.
// Paths should be absolute.  Each path is matched literally.
func AllowExec(paths ...string) Rule

// AllowFork permits the process-fork operation.
// The Go runtime requires this; the Minimal preset includes it.
func AllowFork() Rule

// AllowSignal permits sending and receiving signals.
func AllowSignal() Rule
```

### Rules — Network

```go
// AllowNetwork permits all network operations (inbound and outbound).
func AllowNetwork() Rule

// AllowNetworkOutbound permits outbound network connections only.
func AllowNetworkOutbound() Rule

// AllowNetworkInbound permits inbound network connections only.
func AllowNetworkInbound() Rule

// DenyNetwork is a no-op (network is denied by default) but makes
// intent explicit in rule lists.
func DenyNetwork() Rule
```

### Rules — Mach IPC

```go
// AllowMachLookup permits Mach service lookups by exact global name.
func AllowMachLookup(services ...string) Rule

// AllowMachLookupPrefix permits Mach service lookups matching a prefix.
// Implemented as a regex filter: (global-name-regex #"^prefix.*")
func AllowMachLookupPrefix(prefix string) Rule
```

### Rules — System

```go
// AllowSysctlRead permits reading sysctl values.
// The Go runtime requires this; the Minimal preset includes it.
func AllowSysctlRead() Rule

// AllowIOKit permits IOKit device opens.
func AllowIOKit() Rule

// AllowIPCPosixShm permits POSIX shared memory operations.
func AllowIPCPosixShm() Rule

// AllowIPCPosixSem permits POSIX semaphore operations.
func AllowIPCPosixSem() Rule
```

### Rules — Composition

```go
// Import includes a system sandbox profile by name.
// Example: Import("bsd.sb") emits (import "bsd.sb").
// The Minimal preset already imports bsd.sb.
func Import(profile string) Rule

// Custom injects a raw SBPL fragment into the profile.
// Use for operations not covered by typed constructors.
func Custom(sbpl string) Rule
```

### Presets

```go
// Minimal is the base preset for any Go process.  It imports bsd.sb,
// allows the Go runtime's required operations (sysctl-read, process-fork,
// signal), and enables Mach lookups for DNS and TLS.
// All other presets implicitly include Minimal.
var Minimal Preset

// NoNetwork extends Minimal with no network access.
// File system access must be added via ReadOnly/ReadWrite rules.
var NoNetwork Preset

// NoWrite extends Minimal with read-only file system access.
// No write access, no network.
var NoWrite Preset

// PureComputation extends Minimal with no I/O.
// No file system access (beyond what bsd.sb requires), no network.
var PureComputation Preset
```

Presets are used as the first argument to `Restrict`, with additional rules
layered on:

```go
child, err := seatbelt.Restrict(
    seatbelt.NoNetwork,
    seatbelt.ReadOnly("/usr/share/data"),
    seatbelt.ReadWrite("/tmp/workdir"),
)
```

### Applying the Sandbox

```go
// Restrict re-executes the current process under a sandbox with the
// given rules.  Returns the child process if this is the parent, or
// nil if this is the sandboxed child.
//
// The caller MUST check the return value and handle both cases.
func Restrict(rules ...Rule) (*os.Process, error)

// IsSandboxed reports whether the current process is running inside
// a seatbelt sandbox applied by Restrict.
func IsSandboxed() bool

// Release performs cleanup after the sandboxed process exits.
// Call via defer after the Restrict() nil-child check.
func Release()

// Profile returns the SBPL source of the currently active sandbox,
// or an empty string if not sandboxed.
func Profile() string
```

#### Self-sandboxing (cgo sub-package)

```go
import "github.com/mkke/seatbelt/cgo"

// Apply sandboxes the current process in-place (no re-execution).
// Requires cgo.  The sandbox cannot be removed once applied.
func Apply(rules ...Rule) error

// Check tests whether the given operation on the given path would be
// allowed by the current sandbox.  Requires cgo.
func Check(operation string, path string) (bool, error)
```

---

## Known Limitations and Gotchas

### Go TLS certificate verification

Go's `crypto/x509` on macOS uses Security.framework via Mach IPC to
`com.apple.trustd.agent`.  Sandboxes that block Mach lookups break TLS.  The
`Minimal` preset allows this lookup.  If you use a custom profile without
`Minimal`, either allow the Mach lookup or import
`golang.org/x/crypto/x509roots/fallback` and set
`GODEBUG=x509usefallbackroots=1`.

### Symlink resolution

`/tmp` → `/private/tmp`, `/var` → `/private/var`, `/etc` → `/private/etc`.
SBPL path filters operate on resolved paths.  This library automatically
resolves symlinks and emits both the original and resolved paths.

### Pre-opened file descriptors

File descriptors opened _before_ the sandbox is applied remain usable even if
the sandbox would deny new opens to the same path.  This is a kernel behavior,
not a bug.  When using the re-exec model, this is not an issue because the
sandbox is applied before any application code runs.

### Profile size limit

Serialized SBPL profiles are limited to 65535 bytes by the kernel.  Complex
profiles with many paths may hit this.  The library emits a clear error if
the limit is exceeded.

### sandbox-exec deprecation

Both `sandbox-exec` and `sandbox_init` have been marked deprecated since macOS
10.8 (2012).  As of macOS 15 Sequoia (2024), both remain fully functional and
are relied upon by major projects (Bazel, Nix, Homebrew, Claude Code, Codex).
Apple has not announced a replacement for third-party use.

### AppleScript escape

Built-in profiles historically allowed AppleScript events, enabling a sandboxed
process to send Apple Events to unsandboxed processes.  Generated profiles
do not allow `appleevent-send` unless explicitly requested.

### macOS only

This library is macOS-specific.  On other platforms, `Restrict()` returns
`ErrUnsupportedPlatform`.  Use build tags or runtime checks for portable code.

---

## License

MIT
