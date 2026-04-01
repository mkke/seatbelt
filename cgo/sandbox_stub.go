//go:build !darwin || !cgo

package cgo

import "github.com/mkke/seatbelt"

// Apply is a stub that returns ErrUnsupportedPlatform on non-darwin or non-cgo builds.
func Apply(rules ...seatbelt.Rule) error {
	return seatbelt.ErrUnsupportedPlatform
}

// ApplyProfile is a stub that returns ErrUnsupportedPlatform on non-darwin or non-cgo builds.
func ApplyProfile(profile *seatbelt.Profile) error {
	return seatbelt.ErrUnsupportedPlatform
}

// ApplyWithParams is a stub that returns ErrUnsupportedPlatform on non-darwin or non-cgo builds.
func ApplyWithParams(params map[string]string, rules ...seatbelt.Rule) error {
	return seatbelt.ErrUnsupportedPlatform
}

// Check is a stub that returns ErrUnsupportedPlatform on non-darwin or non-cgo builds.
func Check(pid int, operation string) (bool, error) {
	return false, seatbelt.ErrUnsupportedPlatform
}

// IsApplied always returns false on non-darwin or non-cgo builds.
func IsApplied() bool {
	return false
}
