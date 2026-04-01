package seatbelt

// Rule represents a single sandbox allow-rule.
// Rules are combined to form a complete sandbox profile.
//
// Implementations must return SBPL fragments from sbpl().
// Each fragment should be a complete expression such as
// (allow ...) or (import ...).
type Rule interface {
	sbpl() []string
}
