package seatbelt

import "errors"

var (
	// ErrUnsupportedPlatform is returned when seatbelt is used on a non-macOS platform.
	ErrUnsupportedPlatform = errors.New("seatbelt: macOS required")

	// ErrSandboxExecNotFound is returned when sandbox-exec is not found in the system.
	ErrSandboxExecNotFound = errors.New("seatbelt: sandbox-exec not found")

	// ErrAlreadySandboxed is returned when Restrict is called from an already-sandboxed process.
	ErrAlreadySandboxed = errors.New("seatbelt: process is already sandboxed")

	// ErrProfileTooLarge is returned when the generated SBPL profile exceeds the 65535 byte kernel limit.
	ErrProfileTooLarge = errors.New("seatbelt: profile exceeds 65535 byte limit")

	// ErrNoRules is returned when Restrict or BuildProfile is called without any rules.
	ErrNoRules = errors.New("seatbelt: at least one rule is required")
)
