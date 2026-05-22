package fixhandler

import (
	"sort"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/opa-utils/reporthandling"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"gopkg.in/yaml.v3"
)

// FixHandler is a struct that holds the information of the report to be fixed
type FixHandler struct {
	fixInfo       *metav1.FixInfo
	reportObj     *reporthandlingv2.PostureReport
	localBasePath string

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

// NodeInfo holds extra information about the node
type nodeInfo struct {
	node   *yaml.Node
	parent *yaml.Node

	// position of the node among siblings
	index int
}

// FixInfoMetadata holds the arguments "getFixInfo" function needs to pass to the
// functions it uses
type fixInfoMetadata struct {
	originalList        *[]nodeInfo
	fixedList           *[]nodeInfo
	originalListTracker int
	fixedListTracker    int
	contentToAdd        *[]contentToAdd
	linesToRemove       *[]linesToRemove
}

// contentToAdd holds the information about where to insert the new changes in the existing yaml file
type contentToAdd struct {
	// Line where the fix should be applied to
	line int
	// Content is a string representation of the YAML node that describes a suggested fix
	content string
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

// Content returns the content that will be added, separated by the explicitly
// provided `targetNewline`
func (c *contentToAdd) Content(targetNewline string) string {
	return withNewline(c.content, targetNewline)
}

// LinesToRemove holds the line numbers to remove from the existing yaml file
type linesToRemove struct {
	startLine int
	endLine   int
}

type fileFixInfo struct {
	contentsToAdd *[]contentToAdd
	linesToRemove *[]linesToRemove
}
