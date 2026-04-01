package seatbelt

import (
	"strings"
)

const maxProfileSize = 65535

// Profile represents a complete sandbox profile ready for application.
type Profile struct {
	source string
}

// String returns the SBPL source.
func (p *Profile) String() string {
	return p.source
}

// BuildProfile compiles a set of rules into a complete SBPL profile.
//
// The profile always starts with (version 1) and (deny default).
// If no Import("bsd.sb") rule is present, the Minimal preset is
// automatically prepended (use WithoutMinimal() to suppress this).
func BuildProfile(rules ...Rule) (*Profile, error) {
	if len(rules) == 0 {
		return nil, ErrNoRules
	}

	// Flatten presets and check for bsd.sb import.
	flat := flattenRules(rules)
	hasBsdImport := false
	for _, r := range flat {
		if ir, ok := r.(*importRule); ok && ir.profile == "bsd.sb" {
			hasBsdImport = true
			break
		}
	}

	// Auto-include Minimal if no bsd.sb import is present,
	// unless WithoutMinimal was used (indicated by a withoutMinimalRule).
	hasWithoutMinimal := false
	for _, r := range flat {
		if _, ok := r.(*withoutMinimalRule); ok {
			hasWithoutMinimal = true
			break
		}
	}

	if !hasBsdImport && !hasWithoutMinimal {
		flat = append(flattenRules([]Rule{Minimal}), flat...)
	}

	// Collect SBPL fragments, separate imports from other rules.
	var imports []string
	var other []string
	seenImports := make(map[string]bool)

	for _, r := range flat {
		if _, ok := r.(*withoutMinimalRule); ok {
			continue
		}
		for _, frag := range r.sbpl() {
			if strings.HasPrefix(frag, "(import ") {
				if !seenImports[frag] {
					seenImports[frag] = true
					imports = append(imports, frag)
				}
			} else {
				other = append(other, frag)
			}
		}
	}

	var sb strings.Builder
	sb.WriteString("(version 1)\n")
	sb.WriteString("(deny default)\n")
	for _, imp := range imports {
		sb.WriteString(imp)
		sb.WriteString("\n")
	}
	for _, rule := range other {
		sb.WriteString(rule)
		sb.WriteString("\n")
	}

	source := sb.String()
	if len(source) > maxProfileSize {
		return nil, ErrProfileTooLarge
	}

	return &Profile{source: source}, nil
}

// flattenRules recursively expands Preset rules into their components.
func flattenRules(rules []Rule) []Rule {
	var result []Rule
	for _, r := range rules {
		if p, ok := r.(*Preset); ok {
			result = append(result, flattenRules(p.rules)...)
		} else {
			result = append(result, r)
		}
	}
	return result
}
