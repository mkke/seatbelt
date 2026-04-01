//go:build darwin && cgo

// Package cgo provides in-place sandboxing via the macOS sandbox_init C API.
//
// Unlike the parent seatbelt package which re-executes the process via
// sandbox-exec, this package sandboxes the current process directly using
// cgo calls to sandbox_init. The sandbox cannot be removed once applied.
package cgo

/*
#include <stdlib.h>
#include <stdint.h>

// sandbox_init is deprecated since macOS 10.8 but remains functional.
extern int sandbox_init(const char *profile, uint64_t flags, char **errorbuf);
extern void sandbox_free_error(char *errorbuf);

// sandbox_init_with_parameters is a private API but widely used.
extern int sandbox_init_with_parameters(const char *profile, uint64_t flags,
    const char *const parameters[], char **errorbuf);

// sandbox_check is variadic in C, so we wrap it with a fixed-arg helper.
// filter_type 0 = SANDBOX_FILTER_NONE
extern int sandbox_check(int pid, const char *operation, int filter_type, ...);

static int sandbox_check_no_filter(int pid, const char *operation) {
    return sandbox_check(pid, operation, 0);
}
*/
import "C"

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/mkke/seatbelt"
)

var (
	applied   bool
	appliedMu sync.Mutex
)

// Apply sandboxes the current process in-place using sandbox_init.
// The profile is compiled from the given rules. Once applied, the
// sandbox cannot be removed.
//
// Returns ErrAlreadySandboxed if called more than once.
func Apply(rules ...seatbelt.Rule) error {
	appliedMu.Lock()
	defer appliedMu.Unlock()

	if applied {
		return seatbelt.ErrAlreadySandboxed
	}

	profile, err := seatbelt.BuildProfile(rules...)
	if err != nil {
		return err
	}

	cProfile := C.CString(profile.String())
	defer C.free(unsafe.Pointer(cProfile))

	var errBuf *C.char
	ret := C.sandbox_init(cProfile, 0, &errBuf)
	if ret != 0 {
		var msg string
		if errBuf != nil {
			msg = C.GoString(errBuf)
			C.sandbox_free_error(errBuf)
		}
		return fmt.Errorf("seatbelt: sandbox_init failed: %s", msg)
	}

	applied = true
	return nil
}

// ApplyProfile sandboxes the current process using a pre-built Profile.
func ApplyProfile(profile *seatbelt.Profile) error {
	appliedMu.Lock()
	defer appliedMu.Unlock()

	if applied {
		return seatbelt.ErrAlreadySandboxed
	}

	cProfile := C.CString(profile.String())
	defer C.free(unsafe.Pointer(cProfile))

	var errBuf *C.char
	ret := C.sandbox_init(cProfile, 0, &errBuf)
	if ret != 0 {
		var msg string
		if errBuf != nil {
			msg = C.GoString(errBuf)
			C.sandbox_free_error(errBuf)
		}
		return fmt.Errorf("seatbelt: sandbox_init failed: %s", msg)
	}

	applied = true
	return nil
}

// ApplyWithParams sandboxes the current process with a parameterized
// SBPL profile. Parameters are key-value pairs accessible via
// (param "KEY") in custom SBPL rules.
func ApplyWithParams(params map[string]string, rules ...seatbelt.Rule) error {
	appliedMu.Lock()
	defer appliedMu.Unlock()

	if applied {
		return seatbelt.ErrAlreadySandboxed
	}

	profile, err := seatbelt.BuildProfile(rules...)
	if err != nil {
		return err
	}

	cProfile := C.CString(profile.String())
	defer C.free(unsafe.Pointer(cProfile))

	// Build NULL-terminated array of key, value, NULL.
	cParams := make([]*C.char, 0, len(params)*2+1)
	for k, v := range params {
		ck := C.CString(k)
		cv := C.CString(v)
		cParams = append(cParams, ck, cv)
		defer C.free(unsafe.Pointer(ck))
		defer C.free(unsafe.Pointer(cv))
	}
	cParams = append(cParams, nil)

	var errBuf *C.char
	ret := C.sandbox_init_with_parameters(cProfile, 0, &cParams[0], &errBuf)
	if ret != 0 {
		var msg string
		if errBuf != nil {
			msg = C.GoString(errBuf)
			C.sandbox_free_error(errBuf)
		}
		return fmt.Errorf("seatbelt: sandbox_init_with_parameters failed: %s", msg)
	}

	applied = true
	return nil
}

// Check tests whether the given operation would be allowed by the
// current sandbox for the specified PID. Use os.Getpid() to check
// the current process.
//
// Returns true if the operation is allowed, false if denied.
func Check(pid int, operation string) (bool, error) {
	cOp := C.CString(operation)
	defer C.free(unsafe.Pointer(cOp))

	ret := C.sandbox_check_no_filter(C.int(pid), cOp)
	return ret == 0, nil
}

// IsApplied reports whether Apply has been called successfully.
func IsApplied() bool {
	appliedMu.Lock()
	defer appliedMu.Unlock()
	return applied
}
