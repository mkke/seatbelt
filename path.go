package seatbelt

import (
	"fmt"
	"os"
	"path/filepath"
)

type resolvedPath struct {
	original string
	resolved string
	isDir    bool
}

// resolvePaths resolves symlinks for each path and returns deduplicated
// (original, resolved) pairs. Both are needed because SBPL operates on
// resolved vnodes but users specify logical paths.
func resolvePaths(paths []string) ([]resolvedPath, error) {
	var result []resolvedPath
	seen := make(map[string]bool)

	for _, p := range paths {
		p = filepath.Clean(p)
		if seen[p] {
			continue
		}
		seen[p] = true

		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", p, err)
		}

		resolved, err := filepath.EvalSymlinks(p)
		if err != nil {
			resolved = p
		}

		rp := resolvedPath{
			original: p,
			resolved: resolved,
			isDir:    info.IsDir(),
		}
		result = append(result, rp)
	}
	return result, nil
}

// pathFilter returns the SBPL path filter for a resolved path.
// Directories use (subpath ...), files use (literal ...).
// If original != resolved, a (require-any ...) wrapping both is returned.
func pathFilter(rp resolvedPath) string {
	matcher := "subpath"
	if !rp.isDir {
		matcher = "literal"
	}

	if rp.original == rp.resolved {
		return fmt.Sprintf(`(%s "%s")`, matcher, rp.original)
	}
	return fmt.Sprintf(`(require-any (%s "%s") (%s "%s"))`,
		matcher, rp.original, matcher, rp.resolved)
}

// pathFilters returns the SBPL path filters for multiple resolved paths,
// concatenated with spaces.
func pathFilters(paths []resolvedPath) string {
	var s string
	for i, rp := range paths {
		if i > 0 {
			s += " "
		}
		s += pathFilter(rp)
	}
	return s
}

// resolvePathsBestEffort resolves paths, silently skipping paths that
// don't exist. Returns at least one path or an error.
func resolvePathsBestEffort(paths []string) ([]resolvedPath, error) {
	var result []resolvedPath
	seen := make(map[string]bool)

	for _, p := range paths {
		p = filepath.Clean(p)
		if seen[p] {
			continue
		}
		seen[p] = true

		info, statErr := os.Stat(p)
		if statErr != nil {
			// Path doesn't exist; use it as-is assuming directory.
			resolved, _ := filepath.EvalSymlinks(filepath.Dir(p))
			if resolved == "" {
				resolved = filepath.Dir(p)
			}
			rp := resolvedPath{
				original: p,
				resolved: filepath.Join(resolved, filepath.Base(p)),
				isDir:    true,
			}
			result = append(result, rp)
			continue
		}

		resolved, err := filepath.EvalSymlinks(p)
		if err != nil {
			resolved = p
		}
		result = append(result, resolvedPath{
			original: p,
			resolved: resolved,
			isDir:    info.IsDir(),
		})
	}
	return result, nil
}
