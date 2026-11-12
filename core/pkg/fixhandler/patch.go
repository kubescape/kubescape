package fixhandler

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// maxResourceTrials is the most documents of one manifest changedResources
// tries the fixes of one by one.
const maxResourceTrials = 100

// PatchResult is the proposed fixes of a report as one unified diff.
type PatchResult struct {
	// Patch is the diff, empty when no manifest would change.
	Patch string
	// Files is the number of manifests the patch changes. Resources is the
	// number of resources whose own fixes change their manifest, each counted
	// once: a resource the fixer had nothing to do for is not part of the patch,
	// even when another resource in its file is.
	Files     int
	Resources int
}

// BuildPatch renders the fixes ApplyChanges would write as a single unified
// diff, one section per manifest that changes, without writing anything.
//
// It runs the same fixer ApplyChanges does, on the manifest as it is on disk,
// so the patch holds exactly the edits --output-dir and an in-place fix would
// make. Manifests are only ever opened for reading. Sections are in path order
// and paths are relative to the scan's root, so `git apply` or `patch -p1` run
// from that directory applies the patch.
//
// It is all or nothing: if any manifest cannot be fixed, no patch is returned,
// since one that left a file out would read as complete.
func (h *FixHandler) BuildPatch(ctx context.Context, resourcesToFix []ResourceFixInfo) (*PatchResult, error) {
	names, err := h.patchNames(resourcesToFix)
	if err != nil {
		return nil, err
	}

	fixesByFile := make(map[string][]ResourceFixInfo)
	for _, fix := range resourcesToFix {
		if !fix.inMemory {
			fixesByFile[fix.FilePath] = append(fixesByFile[fix.FilePath], fix)
		}
	}
	sources := make([]string, 0, len(fixesByFile))
	for source := range fixesByFile {
		sources = append(sources, source)
	}
	sort.Slice(sources, func(i, j int) bool { return names[sources[i]] < names[sources[j]] })

	result := &PatchResult{}
	var patch strings.Builder
	var failures []error
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("patch export cancelled: %w", err)
		}
		original, err := readManifest(source)
		if err != nil {
			failures = append(failures, fmt.Errorf("failed to fix file %s: %w", source, err))
			continue
		}
		fixed, err := applyFixToFileContent(ctx, source, original, fixesByFile[source])
		if err != nil {
			failures = append(failures, fmt.Errorf("failed to fix file %s: %w", source, err))
			continue
		}
		section := unifiedDiff(names[source], original, fixed)
		if section == "" {
			continue
		}
		changed, err := changedResources(ctx, source, original, fixesByFile[source])
		if err != nil {
			failures = append(failures, fmt.Errorf("failed to fix file %s: %w", source, err))
			continue
		}
		patch.WriteString(section)
		result.Files++
		result.Resources += changed
	}
	if len(failures) > 0 {
		return nil, errors.Join(failures...)
	}

	result.Patch = patch.String()
	return result, nil
}

// changedResources counts the documents of a manifest whose own fixes change it.
// A document is counted once however many resources the report recorded for it,
// which a scan through overlapping roots does, and not at all when its fixes
// leave it as it is. The fixes of one document are addressed to it alone, so
// applying them by themselves gives what they contribute to the whole.
//
// A file with one document with fixes needs no such trial: the manifest is
// known to have changed, and that document is the one that changed it. Each
// trial edits the whole file, so past maxResourceTrials documents the cost would
// outgrow what a summary is worth; the documents with fixes are then counted
// without it, which still counts a repeated reference once.
func changedResources(ctx context.Context, source, original string, fixes []ResourceFixInfo) (int, error) {
	byDocument := make(map[int][]ResourceFixInfo)
	for _, fix := range fixes {
		byDocument[fix.DocumentIndex] = append(byDocument[fix.DocumentIndex], fix)
	}
	if len(byDocument) == 1 || len(byDocument) > maxResourceTrials {
		return len(byDocument), nil
	}

	changed := 0
	for _, documentFixes := range byDocument {
		if err := ctx.Err(); err != nil {
			return 0, fmt.Errorf("patch export cancelled: %w", err)
		}
		fixed, err := applyFixToFileContent(ctx, source, original, documentFixes)
		if err != nil {
			return 0, err
		}
		if fixed != original {
			changed++
		}
	}
	return changed, nil
}

// patchNames maps each manifest to the slash-separated path its section of the
// patch carries. It uses the layout --output-dir recreates, and refuses a plan
// in which two manifests would share a path or one would reach outside the
// patch's root, the relative path being report input.
func (h *FixHandler) patchNames(resourcesToFix []ResourceFixInfo) (map[string]string, error) {
	sharedRoot, err := h.sharedScanRoot()
	if err != nil {
		return nil, fmt.Errorf("cannot lay out a patch: %w", err)
	}

	names := make(map[string]string)
	claimedBy := make(map[string]string)
	for i := range resourcesToFix {
		resource := &resourcesToFix[i]
		if resource.inMemory {
			continue
		}
		source := resource.FilePath
		if _, planned := names[source]; planned {
			continue
		}

		relativePath, err := manifestRelativePath(resource, sharedRoot)
		if err != nil {
			return nil, err
		}
		name := path.Clean(filepath.ToSlash(relativePath))
		if name == "." || name == ".." || strings.HasPrefix(name, "../") || path.IsAbs(name) || filepath.IsAbs(relativePath) {
			return nil, fmt.Errorf("refusing to put %q in a patch: it is outside the scanned directory", sanitizeForLog(relativePath))
		}
		if other, claimed := claimedBy[name]; claimed {
			return nil, fmt.Errorf("%q and %q would both appear in the patch as %q; export them in separate runs", sanitizeForLog(other), sanitizeForLog(source), name)
		}
		names[source] = name
		claimedBy[name] = source
	}
	return names, nil
}

// readManifest reads a manifest for patching. It opens the file read-only, and
// without waiting on a FIFO, as applyFileChanges does for --output-dir, bounding
// reads up to getMaxManifestSize() to prevent resource exhaustion.
func readManifest(source string) (string, error) {
	bytes, err := readManifestFile(source)
	if err != nil {
		return "", fmt.Errorf("error reading manifest: %w", err)
	}
	return string(bytes), nil
}

// CheckPatchDestination refuses a patch file that could not be written without
// harm, before any work is done: a directory or other special file, a file that
// exists when overwrite is false, a scanned manifest, or the report being
// fixed. The last two would destroy an input, which exporting exists to avoid.
func (h *FixHandler) CheckPatchDestination(destination string, resourcesToFix []ResourceFixInfo, overwrite bool) error {
	destination = filepath.Clean(destination)
	if parent, err := os.Stat(filepath.Dir(destination)); err != nil {
		return fmt.Errorf("cannot write the patch: %w", err)
	} else if !parent.IsDir() {
		return fmt.Errorf("cannot write the patch: %q is not a directory", filepath.Dir(destination))
	}

	sources := make([]string, 0, len(resourcesToFix))
	for i := range resourcesToFix {
		if !resourcesToFix[i].inMemory {
			sources = append(sources, resourcesToFix[i].FilePath)
		}
	}
	if overwritten, ok := h.scannedFiles(sources...).overwritesScannedManifest(destination); ok {
		return fmt.Errorf("refusing to write the patch to %q: it is the scanned manifest %q", destination, sanitizeForLog(overwritten))
	}
	if h.fixInfo != nil && h.fixInfo.ReportFile != "" {
		if report, err := os.Stat(h.fixInfo.ReportFile); err == nil {
			if existing, err := os.Stat(destination); err == nil && os.SameFile(report, existing) {
				return fmt.Errorf("refusing to write the patch to %q: it is the report being fixed", destination)
			}
		}
	}

	existing, err := os.Lstat(destination)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("cannot write the patch: %w", err)
	case existing.IsDir():
		return fmt.Errorf("cannot write the patch: %q is a directory", destination)
	case !overwrite:
		return fmt.Errorf("%q already exists; pass --no-confirm to replace it", destination)
	}
	return nil
}

// WritePatch writes patch to destination so that the file is either complete or
// not there: it is written beside the destination, flushed, and renamed over
// it, and removed again if anything fails. It is created readable by its owner
// only, as a patch holds the manifests' content and may carry what they do not
// intend to share.
func WritePatch(destination, patch string) (err error) {
	destination = filepath.Clean(destination)
	temp, err := os.CreateTemp(filepath.Dir(destination), "."+filepath.Base(destination)+".*.tmp")
	if err != nil {
		return fmt.Errorf("error writing the patch: %w", err)
	}
	defer func() {
		if err != nil {
			_ = temp.Close()
			_ = os.Remove(temp.Name())
		}
	}()

	if _, err = temp.WriteString(patch); err != nil {
		return fmt.Errorf("error writing the patch: %w", err)
	}
	if err = temp.Sync(); err != nil {
		return fmt.Errorf("error writing the patch: failed to flush: %w", err)
	}
	if err = temp.Close(); err != nil {
		return fmt.Errorf("error writing the patch: failed to flush: %w", err)
	}
	if err = os.Rename(temp.Name(), destination); err != nil {
		return fmt.Errorf("error writing the patch: %w", err)
	}
	return nil
}
