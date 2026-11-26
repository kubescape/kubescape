package printer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/pathparse"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling"
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
	if opaSessionObj == nil {
		return nil
	}
	basePath := getBasePathFromMetadata(opaSessionObj)

	var summary *reportsummary.SummaryDetails
	if opaSessionObj.Report != nil {
		summary = &opaSessionObj.Report.SummaryDetails
	}

	failed := make([]scannedResource, 0, len(opaSessionObj.ResourcesResult))
	for resourceID, result := range opaSessionObj.ResourcesResult {
		if !cautils.ResourceStatus(summary, &result).IsFailed() {
			continue
		}
		if res, ok := opaSessionObj.GetResource(resourceID); !ok || res == nil {
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
	if opaSessionObj == nil {
		return
	}
	var summary *reportsummary.SummaryDetails
	if opaSessionObj.Report != nil {
		summary = &opaSessionObj.Report.SummaryDetails
	}

	var caches manifestCache
	for _, scanned := range failedResourcesInPrintOrder(opaSessionObj) {
		resourceID := scanned.resourceID
		result := opaSessionObj.ResourcesResult[resourceID]
		resource, ok := opaSessionObj.GetResource(resourceID)
		if !ok || resource == nil {
			continue
		}

		fmt.Fprintf(prettyPrinter.writer, "\n%s\n", getSeparator("#"))

		if source, ok := opaSessionObj.ResourceSource[resourceID]; ok {
			if srcPath := BestSourcePath(source); srcPath != "" {
				fmt.Fprintf(prettyPrinter.writer, "Source: %s\n", sanitizeText(srcPath))
			}
		}
		fmt.Fprintf(prettyPrinter.writer, "ApiVersion: %s\n", sanitizeText(resource.GetApiVersion()))
		fmt.Fprintf(prettyPrinter.writer, "Kind: %s\n", sanitizeText(resource.GetKind()))
		fmt.Fprintf(prettyPrinter.writer, "Name: %s\n", sanitizeText(resource.GetName()))
		if resource.GetNamespace() != "" {
			fmt.Fprintf(prettyPrinter.writer, "Namespace: %s\n", sanitizeText(resource.GetNamespace()))
		}
		fmt.Fprintf(prettyPrinter.writer, "\n%s\n\n", prettyprinter.ControlCountersForResource(cautils.ControlIDsByStatus(summary, &result)))

		summaryTable := table.NewWriter()
		summaryTable.SetOutputMirror(prettyPrinter.writer)

		summaryTable.Style().Options.SeparateHeader = true
		summaryTable.Style().Options.SeparateRows = true
		summaryTable.Style().Format.HeaderAlign = text.AlignLeft
		summaryTable.Style().Format.Header = text.FormatDefault
		summaryTable.Style().Box = table.StyleBoxRounded

		var source reporthandling.Source
		var sourcePath string
		if src, ok := opaSessionObj.ResourceSource[resourceID]; ok {
			source = src
			sourcePath = BestSourcePath(src)
		}
		lineFor := prettyPrinter.pathLineResolver(opaSessionObj, &caches, scanned)
		var patchFor func([]string) string
		if source.FileType == reporthandling.SourceTypeKustomizeDirectory && source.KustomizeDirectoryName != "" {
			patchFor = func(paths []string) string {
				return cautils.TraceKustomizePatch(resource, paths, source)
			}
		}
		resourceRows := generateResourceRowsWithPreserved(result.ListControls(), summary, resource, prettyPrinter.showEvidence, prettyPrinter.showSecrets, sourcePath, lineFor, opaSessionObj.PreservedValuesForResource(resourceID), patchFor)

		short := utils.CheckShortTerminalWidth(resourceRows, generateResourceHeader(false))
		if short {
			resourceRows = shortFormatResource(resourceRows)
		}
		summaryTable.AppendHeader(generateResourceHeader(short))

		summaryTable.AppendRows(resourceRows)

		summaryTable.Render()

		// A cluster scan has no manifest to point into, so each path gets the
		// command that prints it on the cluster instead of a file and line.
		// Under --hide and --encrypt the names are pseudonyms, so there is nothing
		// on the cluster to point at.
		if prettyPrinter.showEvidence && !prettyPrinter.anonymized && isClusterScan(opaSessionObj) {
			cluster := kubectlCluster{kubeconfig: prettyPrinter.kubeconfig, context: scanContextName(opaSessionObj)}
			if commands := kubectlPointers(result.ListControls(), summary, resource, cluster, prettyPrinter.showSecrets); len(commands) > 0 {
				fmt.Fprintf(prettyPrinter.writer, "\nTo see the current values on the cluster:\n")
				for _, command := range commands {
					fmt.Fprintf(prettyPrinter.writer, "  %s\n", command)
				}
			}
		}
	}

}

// pathLineResolver returns the lookup generateResourceRows uses to turn a fix,
// delete or review path into a line in the manifest, or nil when no line can be resolved for
// this resource. Three things have to hold, and each rules out a real case:
//
//   - --show-evidence is set. Without it no evidence is printed at all, so
//     opening and decoding manifests would be work whose result is discarded.
//   - The session's source paths are real. --hide and --encrypt replace them
//     with pseudonyms, so every open would fail on a path that never existed,
//     warning per manifest about a lookup that was never possible. The scan
//     says once, up front, that lines are unavailable.
//   - The resource came from a file. Cluster-scanned resources have no manifest
//     to point into, and asking the cache for an empty path would try to open
//     "", fail, and warn once per scan about something that was never possible.
//   - The document index is known. getDocIndex reads the "<path>:<index>"
//     convention, which Helm-rendered resources do not carry, and it only
//     applies to LocalWorkload at all.
//
// A nil return is the caller's signal to print paths exactly as before.
func (prettyPrinter *PrettyPrinter) pathLineResolver(opaSessionObj *cautils.OPASessionObj, caches *manifestCache, scanned scannedResource) func(string) (int, bool) {
	if opaSessionObj == nil || !prettyPrinter.showEvidence || scanned.absPath == "" || opaSessionObj.SourcePathsAnonymized {
		return nil
	}

	docIndex, ok := getDocIndex(opaSessionObj, scanned.resourceID)
	if ok {
		resolver := caches.get(scanned.absPath).locationResolver(scanned.absPath, "evidence")
		if resolver == nil {
			return nil
		}

		return func(path string) (int, bool) {
			// ResolveLocation is called directly rather than through
			// resolveFixLocation, which defaults to line 1 when nothing resolves.
			// A fabricated line is worse than none for an auditor reading this
			// column, so an unresolved path degrades to today's bare output -
			// the same choice resolveReviewPathLocations makes for SARIF's
			// related locations.
			location, err := resolver.ResolveLocation(path, docIndex)
			if err != nil || location.Line == 0 {
				return 0, false
			}
			return location.Line, true
		}
	}

	// For resources whose path does not carry an explicit document index (such as
	// Kustomize-rendered resources or Helm templates with actions), check if the
	// originating manifest file on disk can be resolved and map unambiguously to
	// the resource. For fields that come straight from that originating file,
	// resolve their line in that file; for composed or modified fields, keep the
	// file-only form without inventing a line.
	resourceSource := opaSessionObj.ResourceSource[scanned.resourceID]
	if resourceSource.FileType != reporthandling.SourceTypeKustomizeDirectory && resourceSource.FileType != reporthandling.SourceTypeHelmChart {
		return nil
	}

	info, err := os.Stat(scanned.absPath)
	if err != nil || info.IsDir() || !info.Mode().IsRegular() {
		return nil
	}

	resolver := caches.get(scanned.absPath).locationResolver(scanned.absPath, "evidence")
	if resolver == nil {
		return nil
	}

	resource, ok := opaSessionObj.GetResource(scanned.resourceID)
	if !ok || resource == nil {
		return nil
	}

	docIndex, ok = resolver.FindDocumentIndex(resource.GetKind(), resource.GetName(), resource.GetNamespace())
	if !ok {
		return nil
	}

	rawObj, err := resolver.RawDocument(docIndex)
	if err != nil || rawObj == nil {
		return nil
	}
	// The scan writes containers back into the object as []corev1.Container
	// (opaprocessor.removePodData), which getPathValue cannot walk, so no
	// container field would ever count as uncomposed. Normalize both sides to
	// the same generic JSON types, as the value lookups in pathvalue.go do.
	rawObj = normalizeForPathExtraction(rawObj)
	renderedObj := normalizeForPathExtraction(resource.GetObject())

	return func(path string) (int, bool) {
		if !isFieldUncomposed(rawObj, renderedObj, path) {
			return 0, false
		}
		location, err := resolver.ResolveDocumentLocation(path, docIndex)
		if err != nil || location.Line == 0 {
			return 0, false
		}
		return location.Line, true
	}
}

// indexedEntitiesMatch verifies that for every indexed segment in the path (e.g. containers[0]),
// if the element in renderedObj has a "name" key (identifying the entity like a container or volume),
// the corresponding element in rawObj has an identical "name". When entries have no usable identity
// (no name key, or non-string name), they are matched only when their complete entries are equal.
// This prevents attributing line numbers when list entries have been reordered or modified by an overlay.
func indexedEntitiesMatch(rawObj, renderedObj map[string]any, segments []pathparse.Segment) bool {
	for i, seg := range segments {
		if seg.Index >= 0 {
			prefix := segments[:i+1]
			rElem, rOk := getPathValue(renderedObj, prefix)
			rawElem, rawOk := getPathValue(rawObj, prefix)
			if !rOk || !rawOk {
				return false
			}
			rMap, rIsMap := rElem.(map[string]any)
			rawMap, rawIsMap := rawElem.(map[string]any)
			if rIsMap && rawIsMap {
				rName, hasRName := rMap["name"]
				rawName, hasRawName := rawMap["name"]
				if hasRName != hasRawName {
					return false
				}
				rNameStr, isStr := rName.(string)
				if hasRName && isStr && rNameStr != "" {
					if !reflect.DeepEqual(rName, rawName) {
						return false
					}
				} else {
					if !reflect.DeepEqual(rElem, rawElem) {
						return false
					}
				}
			} else {
				if !reflect.DeepEqual(rElem, rawElem) {
					return false
				}
			}
		}
	}
	return true
}

// isFieldUncomposed reports whether path in renderedObj comes straight from rawObj
// without having been added, replaced, or modified by a composer (such as a Kustomize
// overlay or Helm template action).
func isFieldUncomposed(rawObj, renderedObj map[string]any, path string) bool {
	if rawObj == nil || renderedObj == nil {
		return false
	}
	segments, err := pathparse.ParsePath(path)
	if err != nil || len(segments) == 0 {
		return false
	}

	renderedVal, renderedFound := getPathValue(renderedObj, segments)
	rawVal, rawFound := getPathValue(rawObj, segments)

	if renderedFound {
		if !rawFound {
			return false
		}
		if !indexedEntitiesMatch(rawObj, renderedObj, segments) {
			return false
		}
		return valuesMatch(rawVal, renderedVal)
	}

	// If renderedFound is false:
	// A field removed by an overlay or composer while its parent stays (e.g.
	// securityContext: {}) was present in rawObj, so falling back to an ancestor
	// would falsely report the line of the removed field.
	if rawFound {
		return false
	}

	// For an absent fix path, the target field itself does not exist in renderedObj
	// nor in rawObj (e.g. an omitted securityContext setting).
	// Verify that any indexed entities along the path match in identity.
	if !indexedEntitiesMatch(rawObj, renderedObj, segments) {
		return false
	}

	// The line resolver uses the nearest source ancestor. The nearest ancestor
	// must be the same path in both objects before we can report its line.
	// If the path contains an indexed segment (e.g. containers[0]), that indexed
	// entity must exist in renderedObj.
	lastIndexed := -1
	for i, seg := range segments {
		if seg.Index >= 0 {
			lastIndexed = i
		}
	}

	prefix := segments[:len(segments)-1]
	for len(prefix) > 0 {
		if len(prefix) <= lastIndexed {
			// Cannot match an ancestor higher than the indexed entity (e.g. spec cannot stand in for containers[0])
			break
		}
		renderedAncestor, renderedOK := getPathValue(renderedObj, prefix)
		rawAncestor, rawOK := getPathValue(rawObj, prefix)
		// A typed container always encodes its resources as {}, because
		// corev1.Container.Resources is not a pointer, so an empty rendered
		// object may stand for one that is absent.
		if rMap, isMap := renderedAncestor.(map[string]any); renderedOK && isMap && len(rMap) == 0 {
			if !rawOK {
				// Missing from the source too: it carries nothing, so keep
				// looking for an ancestor both objects share.
				renderedOK = false
			} else if rawMap, rawIsMap := rawAncestor.(map[string]any); rawIsMap && len(rawMap) > 0 {
				// The composer removed everything under it, including the
				// line the resolver would report for it.
				return false
			}
		}
		if rawOK != renderedOK {
			return false
		}
		if rawOK {
			// If ancestor is an object with a name, check name match safely without panic
			if rMap, ok := renderedAncestor.(map[string]any); ok {
				if rawMap, rawOk := rawAncestor.(map[string]any); rawOk {
					rName, hasRName := rMap["name"]
					rawName, hasRawName := rawMap["name"]
					if hasRName != hasRawName {
						return false
					}
					if hasRName && !reflect.DeepEqual(rawName, rName) {
						return false
					}
				} else {
					return false
				}
			}
			return true
		}
		prefix = prefix[:len(prefix)-1]
	}
	return false
}

// getPathValue traverses an object following parsed path segments.
func getPathValue(obj any, segments []pathparse.Segment) (any, bool) {
	current := obj
	for _, segment := range segments {
		m, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		val, ok := m[segment.Key]
		if !ok {
			return nil, false
		}
		if segment.Index >= 0 {
			slice, ok := val.([]any)
			if !ok || segment.Index >= len(slice) {
				return nil, false
			}
			current = slice[segment.Index]
		} else {
			current = val
		}
	}
	return current, true
}

// valuesMatch reports whether two field values match in JSON representation.
func valuesMatch(a, b any) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	aj, errA := json.Marshal(a)
	bj, errB := json.Marshal(b)
	if errA == nil && errB == nil {
		return bytes.Equal(aj, bj)
	}
	return reflect.DeepEqual(a, b)
}

func generateResourceRows(controls []resourcesresults.ResourceAssociatedControl, summaryDetails *reportsummary.SummaryDetails, resource workloadinterface.IMetadata, showEvidence bool, showSecrets bool, sourcePath string, lineFor func(string) (int, bool), patchFor ...func([]string) string) []table.Row {
	return generateResourceRowsWithPreserved(controls, summaryDetails, resource, showEvidence, showSecrets, sourcePath, lineFor, nil, patchFor...)
}

func generateResourceRowsWithPreserved(controls []resourcesresults.ResourceAssociatedControl, summaryDetails *reportsummary.SummaryDetails, resource workloadinterface.IMetadata, showEvidence bool, showSecrets bool, sourcePath string, lineFor func(string) (int, bool), preserved map[string]string, patchFor ...func([]string) string) []table.Row {
	var rows []table.Row

	for i := range controls {
		row := make(table.Row, _resourceRowLen)

		if !cautils.ControlStatus(summaryDetails, &controls[i]).IsFailed() {
			continue
		}

		row[resourceColumnURL] = cautils.GetControlLink(controls[i].GetID())
		if showEvidence {
			displayed := cautils.EvidenceControl(summaryDetails, controls[i])
			paths := evidencePathsWithCurrentValues(&displayed, resource, showSecrets, preserved)
			addContainerNameToAssistedRemediation(resource, &paths)
			annotatePathLines(&paths, &displayed, lineFor)
			srcDisplay := sourcePath
			if len(patchFor) > 0 && patchFor[0] != nil {
				if patchFile := patchFor[0](paths); patchFile != "" && patchFile != sourcePath {
					if srcDisplay != "" {
						srcDisplay = fmt.Sprintf("%s (patch: %s)", srcDisplay, patchFile)
					} else {
						srcDisplay = patchFile
					}
				}
			}
			if srcDisplay != "" {
				paths = append([]string{"@ " + srcDisplay}, paths...)
			}
			for j := range paths {
				// file names, current values and container names come from the scanned files
				paths[j] = sanitizeText(paths[j])
			}
			row[resourceColumnPath] = strings.Join(paths, "\n")
		}
		row[resourceColumnName] = controls[i].GetName()

		if summaryDetails != nil && summaryDetails.Controls != nil {
			if c := summaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, controls[i].GetID()); c != nil {
				row[resourceColumnSeverity] = getSeverityColumn(c)
			}
		}

		rows = append(rows, row)
	}

	return rows
}

// annotatePathLines appends " (line N)" to each assisted-remediation entry whose
// path resolves to a line in the manifest - fix, delete and review paths alike.
//
// It has to re-derive which path each entry came from.
// AssistedRemediationPathsWithCurrentValuesFiltered returns all three types
// already rendered into one flat, deduplicated []string, so the path type is
// no longer visible. Each type is re-read from the control and matched by the
// shape it renders to: a fix path as "<path>=<value>", a delete path bare, and
// a review path bare or followed by " (current: <value>)". Any entry may also
// carry a " (<container>)" suffix by this point.
//
// Deriving it here, rather than having the path builders return structured
// values, keeps this local to the pretty-printer: those builders are shared
// with the SARIF, GitLab SAST, HTML and CSV printers, and changing their
// output would change four report formats to annotate one table.
//
// A path whose field is absent from the manifest gets its nearest existing
// ancestor's line, for every path type. That is ResolveLocation's walk-up, and
// it matches what SARIF already reports as a review path's related location,
// so the two outputs point at the same place for the same finding.
func annotatePathLines(paths *[]string, control *resourcesresults.ResourceAssociatedControl, lineFor func(string) (int, bool)) {
	if paths == nil || control == nil || lineFor == nil || len(*paths) == 0 {
		return
	}

	renderings := []struct {
		paths   []string
		matches func(entry, path string) bool
	}{
		{paths: fixPathsToString(control, true), matches: renderedAsFixPath},
		{paths: deletePathsToString(control), matches: renderedAsBarePath},
		{paths: reviewPathsToString(control), matches: renderedAsBarePath},
	}

	// Each entry is annotated at most once. The rendered list is deduplicated
	// on the path with any " (current: ...)" stripped, so a delete path and a
	// review path naming the same field collapse into one entry; and the path
	// builders do not deduplicate, so one control's rules can name the same
	// field twice. Either way several paths can match a single entry, and each
	// would otherwise append its line again.
	annotated := make([]bool, len(*paths))

	// Resolving a path evaluates a yq expression against the manifest, so each
	// distinct path is resolved once however many times it is named.
	type resolution struct {
		line int
		ok   bool
	}
	resolved := make(map[string]resolution)
	lookup := func(path string) (int, bool) {
		if r, seen := resolved[path]; seen {
			return r.line, r.ok
		}
		line, ok := lineFor(path)
		resolved[path] = resolution{line: line, ok: ok}
		return line, ok
	}

	for _, rendering := range renderings {
		for _, path := range rendering.paths {
			for i, entry := range *paths {
				if annotated[i] || !rendering.matches(entry, path) {
					continue
				}
				line, ok := lookup(path)
				if !ok {
					continue
				}
				(*paths)[i] = entry + fmt.Sprintf(" (line %d)", line)
				annotated[i] = true
			}
		}
	}
}

// renderedAsFixPath reports whether entry is path rendered as a fix path,
// "<path>=<value>". Matching on the "=" is what stops "spec.a" from also
// claiming "spec.ab=x".
func renderedAsFixPath(entry, path string) bool {
	return strings.HasPrefix(entry, path+"=")
}

// renderedAsBarePath reports whether entry is path rendered as a delete or
// review path: the path alone, or followed by " (" - a review path's
// " (current: <value>)" or a " (<container>)" hint. Requiring the " (" rather
// than a bare prefix is what stops "spec.containers[0]" from claiming
// "spec.containers[0].image"; unquoted keys cannot contain a space, so the
// suffix cannot be part of a longer path either.
func renderedAsBarePath(entry, path string) bool {
	return entry == path || strings.HasPrefix(entry, path+" (")
}

func addContainerNameToAssistedRemediation(resource workloadinterface.IMetadata, paths *[]string) {
	if resource == nil || paths == nil {
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
		pathStr := ""
		if len(resourceRow) > resourceColumnPath && resourceRow[resourceColumnPath] != nil {
			if s, ok := resourceRow[resourceColumnPath].(string); ok {
				pathStr = s
			} else {
				pathStr = fmt.Sprintf("%v", resourceRow[resourceColumnPath])
			}
		}
		rows[i] = table.Row{fmt.Sprintf("Severity"+strings.Repeat(" ", 13)+": %+v\nControl Name"+strings.Repeat(" ", 9)+": %+v\nDocs"+strings.Repeat(" ", 17)+": %+v\nAssisted Remediation"+strings.Repeat(" ", 1)+": %+v", resourceRow[resourceColumnSeverity], resourceRow[resourceColumnName], resourceRow[resourceColumnURL], strings.ReplaceAll(pathStr, "\n", "\n"+strings.Repeat(" ", 23)))}
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
	if control == nil {
		return nil
	}
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
	if control == nil {
		return nil
	}
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
	if control == nil {
		return nil
	}
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
	if control == nil {
		return nil
	}
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
