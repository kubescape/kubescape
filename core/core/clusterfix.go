package core

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v4/core/pkg/fixhandler"
	"github.com/kubescape/opa-utils/reporthandling"
)

const (
	noClusterFixesRendered = "No fixes could be rendered for this cluster scan."

	// outputDirNotEmpty guards a stray --output-dir . from scattering manifests
	// over a working tree.
	outputDirNotEmpty = "output directory %q is not empty; pass --no-confirm to write into it anyway"
)

// unsafeFileNameChars is everything a resource name could contain that has no
// business in a filename. Replacing rather than rejecting keeps the command
// working for resources with unusual names.
var unsafeFileNameChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// sanitizeFileNameComponent makes one identifier safe to put in a filename.
// Separators become dashes and leading dots are trimmed, so no component can
// contribute a path traversal — ".." collapses to "resource" rather than
// climbing out of the output directory.
func sanitizeFileNameComponent(s string) string {
	s = unsafeFileNameChars.ReplaceAllString(s, "-")
	s = strings.Trim(s, ".-")
	if s == "" {
		return "resource"
	}
	return s
}

// clusterFixFileName names the manifest for one resource as
// <namespace>_<kind>_<name>.yaml. Cluster-scoped resources have no namespace
// segment.
func clusterFixFileName(resource *reporthandling.Resource) string {
	parts := make([]string, 0, 3)
	if namespace := resource.GetNamespace(); namespace != "" {
		parts = append(parts, sanitizeFileNameComponent(namespace))
	}
	parts = append(parts,
		sanitizeFileNameComponent(resource.GetKind()),
		sanitizeFileNameComponent(resource.GetName()),
	)
	return strings.Join(parts, "_") + ".yaml"
}

// clusterResourceLabel identifies a resource in a one-line YAML comment.
func clusterResourceLabel(resource *reporthandling.Resource) string {
	if namespace := resource.GetNamespace(); namespace != "" {
		return fmt.Sprintf("%s/%s/%s", namespace, resource.GetKind(), resource.GetName())
	}
	return fmt.Sprintf("%s/%s", resource.GetKind(), resource.GetName())
}

// printClusterFixes writes the manifests as one YAML document stream, so the
// whole output pipes into `kubectl apply -f -`. Every document is preceded by
// its own `---`, which a YAML stream permits even on the first document and
// which avoids an off-by-one separator.
//
// Only manifests go to w (stdout). Everything else this command says travels
// through logger, which writes to stderr, so the pipe stays clean.
func printClusterFixes(w io.Writer, rendered []fixhandler.RenderedFix) error {
	for _, fix := range rendered {
		if _, err := fmt.Fprintf(w, "---\n# %s\n", clusterResourceLabel(fix.Resource)); err != nil {
			return err
		}
		// The patched manifest's trailing newline depends on the source object,
		// so normalize it: without exactly one, the next `---` would land on the
		// same line as the last field and break the stream.
		if _, err := fmt.Fprintf(w, "%s\n", strings.TrimRight(fix.Manifest, "\n")); err != nil {
			return err
		}
	}
	return nil
}

// writeClusterFixes writes one manifest per resource into dir, returning the
// paths written.
func writeClusterFixes(dir string, rendered []fixhandler.RenderedFix, noConfirm bool) ([]string, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory %q: %w", dir, err)
	}

	if !noConfirm {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("failed to read output directory %q: %w", dir, err)
		}
		if len(entries) > 0 {
			return nil, fmt.Errorf(outputDirNotEmpty, dir)
		}
	}

	cleanDir := filepath.Clean(dir)
	written := make([]string, 0, len(rendered))
	for _, fix := range rendered {
		path := filepath.Join(cleanDir, clusterFixFileName(fix.Resource))

		// Defence in depth behind sanitizeFileNameComponent: the resource name
		// comes from the report, and a manifest must never be written outside
		// the directory the user named.
		if filepath.Dir(path) != cleanDir {
			return written, fmt.Errorf("refusing to write outside %q", cleanDir)
		}

		content := strings.TrimRight(fix.Manifest, "\n") + "\n"
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			return written, fmt.Errorf("failed to write %q: %w", path, err)
		}
		written = append(written, path)
	}
	return written, nil
}

// emitClusterFixes renders the patched manifests for a cluster scan and either
// prints them or writes them to --output-dir.
//
// There is no confirmation prompt here, unlike the file path. That prompt
// guards editing the user's own manifests in place; this writes nothing in
// place and nothing to the cluster, so there is nothing to confirm away.
func (ks *Kubescape) emitClusterFixes(handler *fixhandler.FixHandler, resourcesToFix []fixhandler.ResourceFixInfo, fixInfo *metav1.FixInfo) error {
	rendered, renderErrs := handler.RenderFixes(ks.Context(), resourcesToFix)

	for _, err := range renderErrs {
		logger.L().Ctx(ks.Context()).Warning("failed to render fix", helpers.Error(err))
	}

	if len(rendered) == 0 {
		logger.L().Info(noClusterFixesRendered)
		handler.PrintUnfixedControls(fixhandler.PhasePlanned)
		if len(renderErrs) > 0 {
			return fmt.Errorf("failed to render any fixes, check the logs for more details")
		}
		return nil
	}

	if fixInfo.OutputDir == "" {
		if err := printClusterFixes(os.Stdout, rendered); err != nil {
			return fmt.Errorf("failed to print fixes: %w", err)
		}
		logger.L().Info(fmt.Sprintf("Rendered fixes for %d resource(s). Review them, then apply with: %s fix <report> | kubectl apply -f -",
			len(rendered), cautils.ExecName()))
	} else {
		written, err := writeClusterFixes(fixInfo.OutputDir, rendered, fixInfo.NoConfirm)
		if err != nil {
			return err
		}
		logger.L().Info(fmt.Sprintf("Wrote %d patched manifest(s) to %s. Review them, then apply with: kubectl apply -f %s",
			len(written), fixInfo.OutputDir, fixInfo.OutputDir))
	}

	// PhasePlanned, not PhaseApplied: the manifests are proposals. Nothing has
	// been applied to the cluster, and saying "auto-fixed" would claim it had.
	handler.PrintUnfixedControls(fixhandler.PhasePlanned)

	if len(renderErrs) > 0 {
		return fmt.Errorf("failed to render some fixes, check the logs for more details")
	}
	return nil
}
