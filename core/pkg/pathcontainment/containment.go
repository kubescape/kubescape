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
// It ensures that target resolves within baseDir, resolving symbolic links component
// by component to preserve filesystem semantics before evaluating parent ("..") segments.
// If intermediate components or the leaf do not exist on disk, it preserves the non-existent
// tail while asserting containment of the resolved path.
//
// Behavior:
//   - If baseDir is empty (""), unconstrained mode is assumed and filepath.Clean(target) is returned.
//   - If target is empty or contains NUL bytes ('\x00'), ErrInvalidPath is returned.
//   - If baseDir does not exist or is not a directory, an error is returned.
//   - If target resolves outside baseDir (including via directory traversal or symlinks),
//     ErrPathEscapesWorkspace is returned.
//
// On success with a non-empty baseDir, the canonical, absolute path to target is returned.
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

	// Canonicalize baseDir preserving symlink/.. semantics
	canonicalBase, err := resolveBaseDir(baseDir)
	if err != nil {
		return "", err
	}

	// Resolve target component by component to ensure symlinks are evaluated
	// before any parent ("..") directory traversal occurs.
	resolvedTarget, err := resolveComponentsPreservingSymlinks(canonicalBase, target)
	if err != nil {
		return "", err
	}

	// Verify containment
	rel, err := filepath.Rel(canonicalBase, resolvedTarget)
	if err != nil {
		return "", fmt.Errorf("%w: failed to calculate relative path between baseDir %q and target %q: %v", ErrPathEscapesWorkspace, canonicalBase, resolvedTarget, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: target %q resolves to %q outside baseDir %q", ErrPathEscapesWorkspace, target, resolvedTarget, canonicalBase)
	}

	return resolvedTarget, nil
}

// splitPath splits a path according to platform-specific path separator semantics.
// On Unix-like systems, only '/' is a separator (preserving backslashes in filenames).
// On Windows, both '/' and '\' are recognized as separators.
func splitPath(p string) []string {
	return strings.FieldsFunc(p, func(r rune) bool {
		if r > 127 {
			return false
		}
		return os.IsPathSeparator(uint8(r))
	})
}

// resolveBaseDir resolves baseDir to a canonical, absolute directory path.
// It resolves symbolic links component by component so that parent traversal ("..")
// operates on the physical parent of a symlink target rather than lexically collapsing.
// All components in baseDir must exist and the final resolved path must be a directory.
func resolveBaseDir(baseDir string) (string, error) {
	vol := filepath.VolumeName(baseDir)
	var cur string
	var rest string

	if filepath.IsAbs(baseDir) {
		cur = filepath.Clean(vol + string(filepath.Separator))
		rest = baseDir[len(vol):]
	} else {
		wd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("failed to get current working directory: %w", err)
		}
		canonWd, err := filepath.EvalSymlinks(wd)
		if err != nil {
			return "", fmt.Errorf("failed to resolve symlinks for working directory %q: %w", wd, err)
		}
		cur = canonWd
		rest = baseDir
	}

	parts := splitPath(rest)
	for _, seg := range parts {
		if seg == "" || seg == "." {
			continue
		}

		if seg == ".." {
			fi, statErr := os.Stat(cur)
			if statErr != nil {
				return "", fmt.Errorf("failed to stat path %q: %w", cur, statErr)
			}
			if !fi.IsDir() {
				return "", fmt.Errorf("%w: %q is not a directory", ErrInvalidPath, cur)
			}
			cur = filepath.Dir(cur)
			continue
		}

		next := filepath.Join(cur, seg)
		fi, lstatErr := os.Lstat(next)
		if lstatErr != nil {
			return "", fmt.Errorf("failed to stat baseDir %q: %w", baseDir, lstatErr)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			resolvedSymlink, evalErr := filepath.EvalSymlinks(next)
			if evalErr != nil {
				return "", fmt.Errorf("failed to resolve symlink %q: %w", next, evalErr)
			}
			cur = resolvedSymlink
		} else {
			cur = next
		}
	}

	canonicalBase, err := filepath.EvalSymlinks(cur)
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

	return canonicalBase, nil
}

// resolveComponentsPreservingSymlinks walks target component by component.
// Symlinks are evaluated immediately as they are encountered, so that ".." operates
// on the actual filesystem parent of the resolved directory rather than being
// lexically collapsed.
func resolveComponentsPreservingSymlinks(canonicalBase, target string) (string, error) {
	vol := filepath.VolumeName(target)
	var cur string
	var rest string

	if filepath.IsAbs(target) {
		cur = filepath.Clean(vol + string(filepath.Separator))
		rest = target[len(vol):]
	} else {
		cur = canonicalBase
		rest = target
	}

	parts := splitPath(rest)

	var missingTail []string

	for _, seg := range parts {
		if seg == "" || seg == "." {
			continue
		}

		if seg == ".." {
			if len(missingTail) > 0 {
				missingTail = missingTail[:len(missingTail)-1]
			} else {
				fi, statErr := os.Stat(cur)
				if statErr != nil {
					return "", fmt.Errorf("failed to stat path %q: %w", cur, statErr)
				}
				if !fi.IsDir() {
					return "", fmt.Errorf("%w: %q is not a directory", ErrInvalidPath, cur)
				}
				cur = filepath.Dir(cur)
			}
			continue
		}

		if len(missingTail) > 0 {
			missingTail = append(missingTail, seg)
			continue
		}

		next := filepath.Join(cur, seg)
		fi, lstatErr := os.Lstat(next)
		if lstatErr == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				resolvedSymlink, evalErr := filepath.EvalSymlinks(next)
				if evalErr != nil {
					return "", fmt.Errorf("failed to resolve symlink %q: %w", next, evalErr)
				}
				cur = resolvedSymlink
			} else {
				cur = next
			}
		} else if errors.Is(lstatErr, fs.ErrNotExist) || os.IsNotExist(lstatErr) {
			missingTail = append(missingTail, seg)
		} else {
			return "", fmt.Errorf("failed to stat path %q: %w", next, lstatErr)
		}
	}

	if len(missingTail) > 0 {
		all := append([]string{cur}, missingTail...)
		return filepath.Join(all...), nil
	}
	return cur, nil
}

// IsPathContained reports whether target resolves to a path inside base,
// preventing an untrusted path from escaping the base directory.
// Both base and target are canonicalized by evaluating symlinks.
// Returns false if resolution fails (e.g. nonexistent file, dangling symlink,
// permission error) or if target escapes base.
func IsPathContained(base, target string) bool {
	resolvedBase, err := resolveBaseDir(base)
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
