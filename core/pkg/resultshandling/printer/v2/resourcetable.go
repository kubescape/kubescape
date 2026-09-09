package printer

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
)

var specContainerRegex = regexp.MustCompile(`spec\.(containers|initContainers|ephemeralContainers)\[(\d+)]`)

const (
	resourceColumnSeverity = iota
	resourceColumnName     = iota
	resourceColumnURL      = iota
	resourceColumnPath     = iota
	_resourceRowLen        = iota
)

// failedResourcesInPrintOrder collects the failed resources the table will
// print, paired with the manifest each came from, and orders them so every
// resource of one manifest is visited consecutively.
//
// The order matters beyond tidiness. Evidence line numbers are resolved through
// fixcache's manifestCache, which keeps exactly one manifest's decoded
// documents alive and drops them when the walk reaches the next file. Ranging
// over ResourcesResult directly hands them over in Go's randomised map order,
// which would rebuild a file's resolver once per resource instead of once per
// file. Sorting also makes the printed order reproducible between runs, which
// map order never was.
//
// Unlike the SARIF collector, a resource with no source path is kept rather
// than skipped: cluster scans have no manifests at all, and those resources
// still belong in this table. They carry an empty absPath and simply resolve no
// lines.
func failedResourcesInPrintOrder(opaSessionObj *cautils.OPASessionObj) []scannedResource {
	basePath := getBasePathFromMetadata(*opaSessionObj)

	failed := make([]scannedResource, 0, len(opaSessionObj.ResourcesResult))
	for resourceID, result := range opaSessionObj.ResourcesResult {
		if !result.GetStatus(nil).IsFailed() {
			continue
		}
		if _, ok := opaSessionObj.AllResources[resourceID]; !ok {
			continue
		}

		resourceSource := opaSessionObj.ResourceSource[resourceID]
		relPath := resourceSource.RelativePath

		var absPath string
		if relPath != "" {
			absPath = filepath.Join(effectiveBasePath(resourceSource, basePath), relPath)
		}

		failed = append(failed, scannedResource{
			resourceID: resourceID,
			relPath:    relPath,
			absPath:    absPath,
		})
	}

	return groupByManifest(failed)
}

func (prettyPrinter *PrettyPrinter) resourceTable(opaSessionObj *cautils.OPASessionObj) {

	var caches manifestCache
	for _, scanned := range failedResourcesInPrintOrder(opaSessionObj) {
		resourceID := scanned.resourceID
		result := opaSessionObj.ResourcesResult[resourceID]
		resource := opaSessionObj.AllResources[resourceID]

		fmt.Fprintf(prettyPrinter.writer, "\n%s\n", getSeparator("#"))

		if source, ok := opaSessionObj.ResourceSource[resourceID]; ok {
			fmt.Fprintf(prettyPrinter.writer, "Source: %s\n", source.RelativePath)
		}
		fmt.Fprintf(prettyPrinter.writer, "ApiVersion: %s\n", resource.GetApiVersion())
		fmt.Fprintf(prettyPrinter.writer, "Kind: %s\n", resource.GetKind())
		fmt.Fprintf(prettyPrinter.writer, "Name: %s\n", resource.GetName())
		if resource.GetNamespace() != "" {
			fmt.Fprintf(prettyPrinter.writer, "Namespace: %s\n", resource.GetNamespace())
		}
		fmt.Fprintf(prettyPrinter.writer, "\n%s\n\n", prettyprinter.ControlCountersForResource(result.ListControlsIDs(nil)))

		summaryTable := table.NewWriter()
		summaryTable.SetOutputMirror(prettyPrinter.writer)

		summaryTable.Style().Options.SeparateHeader = true
		summaryTable.Style().Options.SeparateRows = true
		summaryTable.Style().Format.HeaderAlign = text.AlignLeft
		summaryTable.Style().Format.Header = text.FormatDefault
		summaryTable.Style().Box = table.StyleBoxRounded

		var sourcePath string
		if src, ok := opaSessionObj.ResourceSource[resourceID]; ok {
			sourcePath = src.RelativePath
		}
		lineFor := prettyPrinter.fixPathLineResolver(opaSessionObj, &caches, scanned)
		resourceRows := generateResourceRows(result.ListControls(), &opaSessionObj.Report.SummaryDetails, resource, prettyPrinter.showEvidence, prettyPrinter.showSecrets, sourcePath, lineFor)

		short := utils.CheckShortTerminalWidth(resourceRows, generateResourceHeader(false))
		if short {
			resourceRows = shortFormatResource(resourceRows)
		}
		summaryTable.AppendHeader(generateResourceHeader(short))

		summaryTable.AppendRows(resourceRows)

		summaryTable.Render()
	}

}

// fixPathLineResolver returns the lookup generateResourceRows uses to turn a
// fix path into a line in the manifest, or nil when no line can be resolved for
// this resource. Three things have to hold, and each rules out a real case:
//
//   - --show-evidence is set. Without it no evidence is printed at all, so
//     opening and decoding manifests would be work whose result is discarded.
//   - The resource came from a file. Cluster-scanned resources have no manifest
//     to point into, and asking the cache for an empty path would try to open
//     "", fail, and warn once per scan about something that was never possible.
//   - The document index is known. getDocIndex reads the "<path>:<index>"
//     convention, which Helm-rendered resources do not carry, and it only
//     applies to LocalWorkload at all.
//
// A nil return is the caller's signal to print paths exactly as before.
func (prettyPrinter *PrettyPrinter) fixPathLineResolver(opaSessionObj *cautils.OPASessionObj, caches *manifestCache, scanned scannedResource) func(string) (int, bool) {
	if !prettyPrinter.showEvidence || scanned.absPath == "" {
		return nil
	}

	docIndex, ok := getDocIndex(opaSessionObj, scanned.resourceID)
	if !ok {
		return nil
	}

	resolver := caches.get(scanned.absPath).locationResolver(scanned.absPath, "evidence")
	if resolver == nil {
		return nil
	}

	return func(fixPath string) (int, bool) {
		// ResolveLocation is called directly rather than through
		// resolveFixLocation, which defaults to line 1 when nothing resolves.
		// A fabricated line is worse than none for an auditor reading this
		// column, so an unresolved path degrades to today's bare output -
		// the same choice resolveReviewPathLocations makes for SARIF's
		// related locations.
		location, err := resolver.ResolveLocation(fixPath, docIndex)
		if err != nil || location.Line == 0 {
			return 0, false
		}
		return location.Line, true
	}
}

func generateResourceRows(controls []resourcesresults.ResourceAssociatedControl, summaryDetails *reportsummary.SummaryDetails, resource workloadinterface.IMetadata, showEvidence bool, showSecrets bool, sourcePath string, lineFor func(string) (int, bool)) []table.Row {
	var rows []table.Row

	for i := range controls {
		row := make(table.Row, _resourceRowLen)

		if !controls[i].GetStatus(nil).IsFailed() {
			continue
		}

		row[resourceColumnURL] = cautils.GetControlLink(controls[i].GetID())
		if showEvidence {
			paths := AssistedRemediationPathsWithCurrentValuesFiltered(&controls[i], resource, showSecrets)
			addContainerNameToAssistedRemediation(resource, &paths)
			annotateFixPathLines(&paths, &controls[i], lineFor)
			if sourcePath != "" {
				paths = append([]string{"@ " + sourcePath}, paths...)
			}
			row[resourceColumnPath] = strings.Join(paths, "\n")
		}
		row[resourceColumnName] = controls[i].GetName()

		if c := summaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, controls[i].GetID()); c != nil {
			row[resourceColumnSeverity] = getSeverityColumn(c)
		}

		rows = append(rows, row)
	}

	return rows
}

// annotateFixPathLines appends " (line N)" to the assisted-remediation entries
// that came from a FixPath and resolve to a line in the manifest.
//
// It has to re-derive which entries those are.
// AssistedRemediationPathsWithCurrentValuesFiltered returns fix, delete and
// review paths already rendered into one flat, deduplicated []string, so by
// this point the path type is no longer visible: a fix path reads
// "<path>=<value>", a delete path is bare, and a review path carries
// " (current: <value>)". fixPathsToString with onlyPath re-reads the control
// for the bare fix paths, and matching on "<path>=" pins the annotation to
// those entries alone - the "=" is what stops "spec.a" from also matching
// "spec.ab=x".
//
// Deriving it here, rather than having the path builders return structured
// values, keeps this local to the pretty-printer: those builders are shared
// with the SARIF, GitLab SAST, HTML and CSV printers, and changing their
// output would change four report formats to annotate one table.
func annotateFixPathLines(paths *[]string, control *resourcesresults.ResourceAssociatedControl, lineFor func(string) (int, bool)) {
	if lineFor == nil || len(*paths) == 0 {
		return
	}

	for _, fixPath := range fixPathsToString(control, true) {
		line, ok := lineFor(fixPath)
		if !ok {
			continue
		}
		prefix := fixPath + "="
		for i := range *paths {
			if strings.HasPrefix((*paths)[i], prefix) {
				(*paths)[i] += fmt.Sprintf(" (line %d)", line)
			}
		}
	}
}

func addContainerNameToAssistedRemediation(resource workloadinterface.IMetadata, paths *[]string) {
	if resource == nil {
		return
	}
	wl := workloadinterface.NewWorkloadObj(resource.GetObject())
	for i := range *paths {
		match := specContainerRegex.FindStringSubmatch((*paths)[i])
		if len(match) != 3 {
			continue
		}
		index, err := strconv.Atoi(match[2])
		if err != nil {
			continue
		}
		var containerName string
		switch match[1] {
		case "containers":
			containers, _ := wl.GetContainers()
			if index < len(containers) {
				containerName = containers[index].Name
			}
		case "initContainers":
			containers, _ := wl.GetInitContainers()
			if index < len(containers) {
				containerName = containers[index].Name
			}
		case "ephemeralContainers":
			containers, _ := wl.GetEphemeralContainers()
			if index < len(containers) {
				containerName = containers[index].Name
			}
		}
		if containerName == "" {
			continue
		}
		(*paths)[i] = (*paths)[i] + " (" + containerName + ")"
	}
}

func generateResourceHeader(short bool) table.Row {
	if short {
		return table.Row{"Resources"}
	} else {
		return table.Row{"Severity", "Control name", "Docs", "Assisted remediation"}
	}
}

func shortFormatResource(resourceRows []table.Row) []table.Row {
	rows := make([]table.Row, len(resourceRows))
	for i, resourceRow := range resourceRows {
		rows[i] = table.Row{fmt.Sprintf("Severity"+strings.Repeat(" ", 13)+": %+v\nControl Name"+strings.Repeat(" ", 9)+": %+v\nDocs"+strings.Repeat(" ", 17)+": %+v\nAssisted Remediation"+strings.Repeat(" ", 1)+": %+v", resourceRow[resourceColumnSeverity], resourceRow[resourceColumnName], resourceRow[resourceColumnURL], strings.ReplaceAll(resourceRow[resourceColumnPath].(string), "\n", "\n"+strings.Repeat(" ", 23)))}
	}
	return rows
}

type Matrix [][]string

func (a Matrix) Len() int      { return len(a) }
func (a Matrix) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a Matrix) Less(i, j int) bool {
	l := len(a[i])
	for k := range l {
		if a[i][k] < a[j][k] {
			return true
		} else if a[i][k] > a[j][k] {
			return false
		}
	}
	return true
}

func fixPathsToString(control *resourcesresults.ResourceAssociatedControl, onlyPath bool) []string {
	var paths []string

	for j := range control.ResourceAssociatedRules {
		for k := range control.ResourceAssociatedRules[j].Paths {
			if p := control.ResourceAssociatedRules[j].Paths[k].FixPath.Path; p != "" {
				if onlyPath {
					paths = append(paths, p)
				} else {
					v := control.ResourceAssociatedRules[j].Paths[k].FixPath.Value
					paths = append(paths, fmt.Sprintf("%s=%s", p, v))
				}
			}
		}
	}
	return paths
}

func deletePathsToString(control *resourcesresults.ResourceAssociatedControl) []string {
	var paths []string

	for j := range control.ResourceAssociatedRules {
		for k := range control.ResourceAssociatedRules[j].Paths {
			if p := control.ResourceAssociatedRules[j].Paths[k].DeletePath; p != "" {
				paths = append(paths, p)
			}
		}
	}
	return paths
}

func reviewPathsToString(control *resourcesresults.ResourceAssociatedControl) []string {
	var paths []string

	for j := range control.ResourceAssociatedRules {
		for k := range control.ResourceAssociatedRules[j].Paths {
			if p := control.ResourceAssociatedRules[j].Paths[k].ReviewPath; p != "" {
				paths = append(paths, p)
			}
		}
	}
	return paths
}

func AssistedRemediationPathsToString(control *resourcesresults.ResourceAssociatedControl) []string {
	paths := append(fixPathsToString(control, false), append(deletePathsToString(control), reviewPathsToString(control)...)...)
	return deduplicatePaths(paths)
}

func deduplicatePaths(paths []string) []string {
	if len(paths) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	deduped := make([]string, 0, len(paths))
	for _, path := range paths {
		key := dedupPathKey(path)
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, path)
		}
	}
	return deduped
}

// dedupPathKey strips the " (current: <value>)" suffix appended by evidence enrichment so a
// bare path (as emitted by fix/delete/review paths) and its enriched failed-path counterpart
// are recognized as referring to the same field.
func dedupPathKey(path string) string {
	if idx := strings.Index(path, " (current: "); idx >= 0 {
		return path[:idx]
	}
	return path
}
