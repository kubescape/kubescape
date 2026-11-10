package v1

import (
	"errors"
	"io"
	"strings"

	"github.com/kubescape/kubescape/v4/core/cautils"
)

type FixInfo struct {
	ReportFile     string // path to report file (mandatory)
	NoConfirm      bool   // if true, no confirmation will be given to the user before applying the fix
	SkipUserValues bool   // if true, user values will not be changed
	DryRun         bool   // if true, no changes will be applied
	Interactive    bool   // if true, ask for confirmation before applying fixes to each individual resource
	// BasePath, if set, restricts fixes to this directory: the report's own
	// recorded scan location (which the report itself controls) must resolve
	// inside it, or NewFixHandler refuses to proceed. Use this when the
	// report file comes from a source you don't fully trust (e.g. a shared
	// CI artifact) - without it, the report's recorded location is trusted
	// as-is, as it always has been.
	BasePath             string
	ContainerProfilePath string // Path to an optional ContainerProfile JSON file
	// IncludeControls and SkipControls narrow which failed controls are
	// remediated. Matching is case-insensitive on the control ID, and
	// SkipControls wins over IncludeControls, mirroring the scan-side
	// --include-controls/--skip-controls pair.
	IncludeControls []string
	SkipControls    []string
	// OutputDir, when set, receives the fixes instead of their default
	// destination. For a file-based report that default is the manifests
	// themselves: with OutputDir the fixed copies are written there, mirroring
	// the scanned tree, and the originals are left untouched. For a cluster scan
	// report, which has no manifests to rewrite, one patched manifest per
	// resource is written there instead of being printed to stdout.
	OutputDir string
	// OutputPatch, when set, receives the fixes of a file-based report as one
	// unified diff, instead of the manifests being rewritten. No manifest is
	// modified, and an existing file at the path is replaced only with NoConfirm.
	// It is applied from the scan's root with `git apply` or `patch -p1`.
	OutputPatch string
	// KustomizeDir, when set, writes a kustomization.yaml and JSON 6902
	// patch files for Helm-rendered resources into this directory.
	// The patches can be applied via:
	//
	//   kustomize build <dir> | kubectl apply -f -
	//
	// This is opt-in and does not affect the normal fix pipeline.
	KustomizeDir string
	// PostRendererDir, when set, writes an executable post-renderer script into this
	// directory. The script accepts Helm-rendered manifests on stdin, applies the
	// Kustomize patches from KustomizeDir, and writes the remediated manifests to stdout.
	// Requires KustomizeDir to also be set.
	//
	//   helm install my-release ./chart --post-renderer <PostRendererDir>/renderer.sh
	//
	PostRendererDir string
	// HelmValueOptions carries user-supplied Helm value overrides and release identity
	// used to reproduce scan-time chart renders during fix generation.
	HelmValueOptions cautils.HelmValueOptions
	// Writer is the destination writer for stdout-directed output (such as cluster fixes); defaults to os.Stdout when nil.
	Writer io.Writer
}

// ValidateOutputPatch refuses the combinations in which OutputPatch would do
// less than it says. OutputDir and DryRun already stop the manifests from being
// rewritten, so combining either with it leaves unclear which one decides the
// outcome, and silently honouring one of them would hide that. It is checked by
// the command and again by Kubescape.Fix, so a caller of the core API is held to
// the same rules. It is nil when OutputPatch is empty.
func (f *FixInfo) ValidateOutputPatch() error {
	if f.OutputPatch == "" {
		return nil
	}
	if strings.TrimSpace(f.OutputPatch) == "" {
		return errors.New("--output-patch needs a file path")
	}
	if f.OutputDir != "" {
		return errors.New("--output-patch cannot be combined with --output-dir: choose a patch or fixed copies")
	}
	if f.DryRun {
		return errors.New("--output-patch cannot be combined with --dry-run: exporting a patch already leaves the manifests untouched")
	}
	return nil
}
