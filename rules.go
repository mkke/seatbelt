package seatbelt

import "fmt"

// fileRule allows file operations on specific paths.
//
// In addition to the primary file-read*/file-write* allowance, each
// rule also emits matching file-issue-extension allowances for the
// extension classes listed in extClasses. This mirrors Apple's own
// system-profile idiom (the `read-and-issue-extensions` and
// `read-write-and-issue-extensions` helpers defined throughout
// /System/Library/Sandbox/Profiles/) and is required for operations
// that dispatch into the kernel's extension-class check — most
// notably writable shared mmap (MAP_SHARED|PROT_WRITE), which SQLite
// uses for its -shm files. Without the extension grant, the mmap
// fails with EPERM (SQLITE_IOERR_SHMMAP) on macOS 14+ even when
// file-read* and file-write* are allowed on the containing path.
type fileRule struct {
	ops        []string // e.g. "file-read*", "file-write*", "file-read-metadata"
	paths      []string
	extClasses []string // extension classes for the file-issue-extension grant
}

func (r *fileRule) sbpl() []string {
	resolved, err := resolvePathsBestEffort(r.paths)
	if err != nil || len(resolved) == 0 {
		return nil
	}
	ops := ""
	for i, op := range r.ops {
		if i > 0 {
			ops += " "
		}
		ops += op
	}
	filter := pathFilters(resolved)
	// When a rule has more than one resolved path, pathFilters
	// returns a space-separated list of subpath/literal clauses. A
	// plain (allow OPS clauses...) rule treats them as match-any by
	// default, but inside (require-all ...) they become match-all —
	// and no single file is in all subpaths at once, so the rule
	// never fires. Wrap in (require-any ...) for the
	// issue-extension branch so the filters stay match-any.
	extFilter := filter
	if len(resolved) > 1 {
		extFilter = "(require-any " + filter + ")"
	}
	result := []string{fmt.Sprintf("(allow %s %s)", ops, filter)}
	for _, class := range r.extClasses {
		result = append(result, fmt.Sprintf(
			`(allow file-issue-extension (require-all (extension-class "%s") %s))`,
			class, extFilter))
	}
	return result
}

// ReadOnly allows reading files and metadata under the given paths.
// Also grants file-issue-extension with the read extension class so
// shared read mappings (mmap MAP_SHARED|PROT_READ) work on macOS 14+.
func ReadOnly(paths ...string) Rule {
	return &fileRule{
		ops:        []string{"file-read*", "file-read-metadata"},
		paths:      paths,
		extClasses: []string{"com.apple.app-sandbox.read"},
	}
}

// ReadWrite allows reading and writing files under the given paths.
// Also grants file-issue-extension with both read and read-write
// extension classes so writable shared mappings work on macOS 14+
// — notably SQLite's -shm mmap, which fails with EPERM without
// the read-write extension.
func ReadWrite(paths ...string) Rule {
	return &fileRule{
		ops:        []string{"file-read*", "file-write*", "file-read-metadata"},
		paths:      paths,
		extClasses: []string{"com.apple.app-sandbox.read", "com.apple.app-sandbox.read-write"},
	}
}

// WriteOnly allows writing (but not reading) files under the given paths.
// Also grants file-issue-extension with the read-write extension class.
func WriteOnly(paths ...string) Rule {
	return &fileRule{
		ops:        []string{"file-write*"},
		paths:      paths,
		extClasses: []string{"com.apple.app-sandbox.read-write"},
	}
}

// processRule allows process operations, optionally on specific paths.
type processRule struct {
	op    string // "process-exec" or "process-fork"
	paths []string
}

func (r *processRule) sbpl() []string {
	if r.op == "process-fork" {
		return []string{"(allow process-fork)"}
	}
	if len(r.paths) == 0 {
		return []string{fmt.Sprintf("(allow %s)", r.op)}
	}
	resolved, err := resolvePathsBestEffort(r.paths)
	if err != nil || len(resolved) == 0 {
		return nil
	}
	return []string{fmt.Sprintf("(allow %s %s)", r.op, pathFilters(resolved))}
}

// AllowExec permits executing the specified binaries.
func AllowExec(paths ...string) Rule {
	return &processRule{op: "process-exec", paths: paths}
}

// AllowFork permits the process-fork operation.
func AllowFork() Rule {
	return &processRule{op: "process-fork"}
}

// networkRule allows network operations.
type networkRule struct {
	op string // "network*", "network-outbound", "network-inbound"
}

func (r *networkRule) sbpl() []string {
	return []string{fmt.Sprintf("(allow %s)", r.op)}
}

// AllowNetwork permits all network operations.
func AllowNetwork() Rule {
	return &networkRule{op: "network*"}
}

// AllowNetworkOutbound permits outbound network connections only.
func AllowNetworkOutbound() Rule {
	return &networkRule{op: "network-outbound"}
}

// AllowNetworkInbound permits inbound network connections only.
func AllowNetworkInbound() Rule {
	return &networkRule{op: "network-inbound"}
}

// noopRule produces no SBPL output.
type noopRule struct{}

func (r *noopRule) sbpl() []string { return nil }

// DenyNetwork is a no-op (network is denied by default) that makes
// intent explicit in rule lists.
func DenyNetwork() Rule {
	return &noopRule{}
}

// signalRule allows the signal operation.
type signalRule struct{}

func (r *signalRule) sbpl() []string {
	return []string{"(allow signal)"}
}

// AllowSignal permits sending and receiving signals.
func AllowSignal() Rule {
	return &signalRule{}
}

// machRule allows Mach service lookups.
type machRule struct {
	services []string
	prefix   string
}

func (r *machRule) sbpl() []string {
	if r.prefix != "" {
		return []string{fmt.Sprintf(`(allow mach-lookup (global-name-regex #"^%s"))`, r.prefix)}
	}
	if len(r.services) == 0 {
		return nil
	}
	filters := ""
	for i, s := range r.services {
		if i > 0 {
			filters += " "
		}
		filters += fmt.Sprintf(`(global-name "%s")`, s)
	}
	return []string{fmt.Sprintf("(allow mach-lookup %s)", filters)}
}

// AllowMachLookup permits Mach service lookups by exact global name.
func AllowMachLookup(services ...string) Rule {
	return &machRule{services: services}
}

// AllowMachLookupPrefix permits Mach service lookups matching a prefix.
func AllowMachLookupPrefix(prefix string) Rule {
	return &machRule{prefix: prefix}
}

// sysctlRule allows sysctl operations.
type sysctlRule struct {
	op string
}

func (r *sysctlRule) sbpl() []string {
	return []string{fmt.Sprintf("(allow %s)", r.op)}
}

// AllowSysctlRead permits reading sysctl values.
func AllowSysctlRead() Rule {
	return &sysctlRule{op: "sysctl-read"}
}

// iokitRule allows IOKit device opens.
type iokitRule struct{}

func (r *iokitRule) sbpl() []string {
	return []string{"(allow iokit-open)"}
}

// AllowIOKit permits IOKit device opens.
func AllowIOKit() Rule {
	return &iokitRule{}
}

// ipcRule allows IPC operations.
type ipcRule struct {
	op string
}

func (r *ipcRule) sbpl() []string {
	return []string{fmt.Sprintf("(allow %s)", r.op)}
}

// AllowIPCPosixShm permits POSIX shared memory operations.
func AllowIPCPosixShm() Rule {
	return &ipcRule{op: "ipc-posix-shm-read* ipc-posix-shm-write-create ipc-posix-shm-write-data ipc-posix-shm-write-unlink"}
}

// AllowIPCPosixSem permits POSIX semaphore operations.
func AllowIPCPosixSem() Rule {
	return &ipcRule{op: "ipc-posix-sem"}
}

// importRule imports a system sandbox profile.
type importRule struct {
	profile string
}

func (r *importRule) sbpl() []string {
	return []string{fmt.Sprintf(`(import "%s")`, r.profile)}
}

// Import includes a system sandbox profile by name.
func Import(profile string) Rule {
	return &importRule{profile: profile}
}

// customRule injects raw SBPL.
type customRule struct {
	source string
}

func (r *customRule) sbpl() []string {
	return []string{r.source}
}

// Custom injects a raw SBPL fragment into the profile.
func Custom(sbpl string) Rule {
	return &customRule{source: sbpl}
}
