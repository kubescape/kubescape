package fixhandler

import (
	"sort"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/opa-utils/reporthandling"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

// FixHandler is a struct that holds the information of the report to be fixed
type FixHandler struct {
	fixInfo       *metav1.FixInfo
	reportObj     *reporthandlingv2.PostureReport
	localBasePath string
	controls      controlSelector

	// unfixedControls is populated by PrepareResourcesToFix with every failed
	// (resource, control) tuple that the fixer cannot or will not auto-remediate.
	unfixedControls []UnfixedControl
	// fixedControlsCount is the number of failed (resource, control) tuples that
	// produced at least one yaml expression to apply.
	fixedControlsCount int
}

// ResourceFixInfo is a struct that holds the information about the resource that needs to be fixed
type ResourceFixInfo struct {
	YamlExpressions map[string]armotypes.FixPath
	Resource        *reporthandling.Resource
	FilePath        string
	DocumentIndex   int

	// failedControls and fixedCount let a resource be withdrawn after its
	// controls have already been tallied: the entries are re-reported as
	// unfixed and the count of fully fixed controls is given back.
	failedControls []UnfixedControl
	fixedCount     int
	fileKey        string

	// inMemory marks a resource with no manifest on disk — a live object from a
	// cluster scan. Its fix is rendered from the scanned object by RenderFixes
	// rather than written back by ApplyChanges, and FilePath is empty.
	inMemory bool
}

// HelmFixSuggestion describes a fix for a Helm-rendered resource. We do not
// edit chart templates directly: the rendered line numbers in the yq fix paths
// don't reliably map back to template lines (this was the underlying bug
// behind PRs #1215/#1551/#1620/#1628 and the rationale for issue #1772).
// Instead, we surface the rule's fix path together with the .Values.* keys
// statically referenced by the source template, so the user can edit
// values.yaml deliberately.
type HelmFixSuggestion struct {
	Resource     *reporthandling.Resource
	ChartPath    string              // on-disk chart root (Source.HelmPath)
	ChartName    string              // Source.HelmChartName
	TemplateFile string              // chart-relative, e.g. "templates/deployment.yaml"
	ValuesPaths  []string            // candidate dotted .Values.* keys referenced by the template; may be empty
	FixPaths     []armotypes.FixPath // rule-suggested rendered-YAML edits, for the user to translate into values.yaml
}

// UnfixedControl describes a failed (resource, control) tuple for which `kubescape fix`
// did not produce an automatic remediation. The user must address these manually.
type UnfixedControl struct {
	ControlID    string
	ControlName  string
	ResourceName string
	ResourceKind string
	FilePath     string
	// Reason is a short, user-facing explanation of why this control was not auto-fixed
	// (e.g. "no auto-fix available", "skipped: file not found", "skipped: not a YAML source").
	Reason string
}

func withNewline(content, targetNewline string) string {
	replaceNewlines := map[string]bool{
		unixNewline:    true,
		windowsNewline: true,
		oldMacNewline:  true,
	}
	replaceNewlines[targetNewline] = false

	newlinesToReplace := make([]string, len(replaceNewlines))
	i := 0
	for k := range replaceNewlines {
		newlinesToReplace[i] = k
		i++
	}

	// To ensure that we fully replace Windows newlines (CR LF), and not
	// corrupt them into two new newlines (CR CR or LF LF) by partially
	// replacing either CR or LF, we have to ensure we replace longer
	// Windows newlines first
	sort.Slice(newlinesToReplace, func(i int, j int) bool {
		return len(newlinesToReplace[i]) > len(newlinesToReplace[j])
	})

	// strings.Replacer takes a flat list of (oldVal, newVal) pairs, so we
	// need to allocate twice the space and assign accordingly
	newlinesOldNew := make([]string, 2*len(replaceNewlines))
	i = 0
	for _, nl := range newlinesToReplace {
		newlinesOldNew[2*i] = nl
		newlinesOldNew[2*i+1] = targetNewline
		i++
	}

	replacer := strings.NewReplacer(newlinesOldNew...)
	return replacer.Replace(content)
}
