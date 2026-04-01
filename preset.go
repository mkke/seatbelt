package seatbelt

// Preset is a pre-configured set of rules for common use cases.
// Presets implement Rule so they can be composed with other rules.
type Preset struct {
	rules []Rule
}

func (p *Preset) sbpl() []string {
	var result []string
	for _, r := range p.rules {
		result = append(result, r.sbpl()...)
	}
	return result
}

var (
	// Minimal provides the minimum rules for a Go process to run.
	// It imports bsd.sb and allows the Go runtime's required operations.
	Minimal = &Preset{rules: []Rule{
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

	// NoNetwork extends Minimal with no network access.
	// File system access must be added via ReadOnly/ReadWrite rules.
	NoNetwork = &Preset{rules: append(copyRules(Minimal.rules), DenyNetwork())}

	// NoWrite extends Minimal with read-only file system access and no network.
	NoWrite = &Preset{rules: append(copyRules(Minimal.rules),
		DenyNetwork(),
		ReadOnly("/"),
	)}

	// PureComputation extends Minimal with no I/O beyond what bsd.sb requires.
	// No file system access, no network.
	PureComputation = &Preset{rules: copyRules(Minimal.rules)}
)

func copyRules(rules []Rule) []Rule {
	c := make([]Rule, len(rules))
	copy(c, rules)
	return c
}

// withoutMinimalRule is a marker rule that suppresses auto-inclusion of Minimal.
type withoutMinimalRule struct{}

func (r *withoutMinimalRule) sbpl() []string { return nil }

// WithoutMinimal suppresses the automatic inclusion of the Minimal preset
// in BuildProfile. Use this for full control over the sandbox profile.
func WithoutMinimal() Rule {
	return &withoutMinimalRule{}
}
