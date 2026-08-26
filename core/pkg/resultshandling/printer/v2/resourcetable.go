package printer

import (
	"fmt"
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

func (prettyPrinter *PrettyPrinter) resourceTable(opaSessionObj *cautils.OPASessionObj) {

	for resourceID, result := range opaSessionObj.ResourcesResult {
		if !result.GetStatus(nil).IsFailed() {
			continue
		}
		resource, ok := opaSessionObj.AllResources[resourceID]
		if !ok {
			continue
		}
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
		resourceRows := generateResourceRows(result.ListControls(), &opaSessionObj.Report.SummaryDetails, resource, prettyPrinter.showEvidence, prettyPrinter.showSecrets, sourcePath)

		short := utils.CheckShortTerminalWidth(resourceRows, generateResourceHeader(false))
		if short {
			resourceRows = shortFormatResource(resourceRows)
		}
		summaryTable.AppendHeader(generateResourceHeader(short))

		summaryTable.AppendRows(resourceRows)

		summaryTable.Render()
	}

}

func generateResourceRows(controls []resourcesresults.ResourceAssociatedControl, summaryDetails *reportsummary.SummaryDetails, resource workloadinterface.IMetadata, showEvidence bool, showSecrets bool, sourcePath string) []table.Row {
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
