package pathcontainment

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

var (
	// ErrPathEscapesWorkspace indicates that the resolved target path lies outside the workspace root.
	ErrPathEscapesWorkspace = errors.New("path escapes workspace root")

	// ErrInvalidPath indicates an empty path or a path containing prohibited characters (e.g. NUL bytes).
	ErrInvalidPath = errors.New("invalid path")
)

// ResolveContainedPath validates and canonicalizes target relative to baseDir.
// It ensures that target resolves within baseDir, resolving symbolic links and
// walking existing ancestors if parts of the tail do not yet exist on disk.
//
// Behavior:
//   - If baseDir is empty (""), unconstrained mode is assumed and filepath.Clean(target) is returned.
//   - If target is empty or contains NUL bytes ('\x00'), ErrInvalidPath is returned.
//   - If baseDir does not exist or is not a directory, an error is returned.
//   - If target resolves outside baseDir (including via directory traversal or symlinks),
//     ErrPathEscapesWorkspace is returned.
//
// On success, the canonical, absolute path to target is returned.
func ResolveContainedPath(baseDir, target string) (string, error) {
	if target == "" || strings.ContainsRune(target, 0) {
		return "", ErrInvalidPath
	}
	if strings.ContainsRune(baseDir, 0) {
		return "", ErrInvalidPath
	}

	// Unconstrained pass-through mode
	if baseDir == "" {
		return filepath.Clean(target), nil
	}

	// Canonicalize baseDir
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return "", fmt.Errorf("failed to determine absolute path for baseDir %q: %w", baseDir, err)
	}
	canonicalBase, err := filepath.EvalSymlinks(absBase)
	if err != nil {
		return "", fmt.Errorf("failed to resolve symlinks for baseDir %q: %w", baseDir, err)
	}
	baseInfo, err := os.Stat(canonicalBase)
	if err != nil {
		return "", fmt.Errorf("failed to stat baseDir %q: %w", baseDir, err)
	}
	if !baseInfo.IsDir() {
		return "", fmt.Errorf("baseDir %q is not a directory", baseDir)
	}

	// Normalize target against canonicalBase
	var fullTarget string
	if filepath.IsAbs(target) {
		fullTarget = filepath.Clean(target)
	} else {
		fullTarget = filepath.Join(canonicalBase, target)
	}

	// Canonicalize target (including symlink resolution and missing tail handling)
	resolvedTarget, err := resolveSymlinksWithMissingTail(fullTarget)
	if err != nil {
		return "", fmt.Errorf("failed to resolve path %q: %w", target, err)
	}

	// Verify containment
	rel, err := filepath.Rel(canonicalBase, resolvedTarget)
	if err != nil {
		return "", fmt.Errorf("failed to calculate relative path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: target %q resolves to %q outside baseDir %q", ErrPathEscapesWorkspace, target, resolvedTarget, canonicalBase)
	}

	return resolvedTarget, nil
}

// resolveSymlinksWithMissingTail resolves symbolic links in path. If leaf components
// or subdirectories do not exist yet on disk, it finds the deepest existing ancestor,
// resolves its symbolic links, and appends the non-existent tail.
// If an existing component is a broken or dangling symlink, an error is returned.
func resolveSymlinksWithMissingTail(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved, nil
	}
	if !errors.Is(err, fs.ErrNotExist) && !os.IsNotExist(err) {
		return "", err
	}

	cur := path
	var missingParts []string
	for {
		_, lstatErr := os.Lstat(cur)
		if lstatErr == nil {
			// cur exists. If it is a symlink, EvalSymlinks must resolve;
			// if EvalSymlinks fails on an existing symlink, it is dangling.
			resolvedCur, evalErr := filepath.EvalSymlinks(cur)
			if evalErr != nil {
				return "", fmt.Errorf("failed to resolve symlink %q: %w", cur, evalErr)
			}
			all := append([]string{resolvedCur}, missingParts...)
			return filepath.Join(all...), nil
		} else if !errors.Is(lstatErr, fs.ErrNotExist) && !os.IsNotExist(lstatErr) {
			return "", lstatErr
		}

		parent := filepath.Dir(cur)
		if parent == cur {
			return "", err
		}
		missingParts = append([]string{filepath.Base(cur)}, missingParts...)
		cur = parent
	}
}

// IsPathContained reports whether target resolves to a path inside base,
// preventing an untrusted path from escaping the base directory.
// Both base and target are canonicalized by evaluating symlinks.
// Returns false if resolution fails (e.g. nonexistent file, dangling symlink,
// permission error) or if target escapes base.
func IsPathContained(base, target string) bool {
	resolvedBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		return false
	}
	resolvedTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(resolvedBase, resolvedTarget)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
