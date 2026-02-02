package printer

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
)

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

		resourceRows := generateResourceRows(result.ListControls(), &opaSessionObj.Report.SummaryDetails, resource)

		short := utils.CheckShortTerminalWidth(resourceRows, generateResourceHeader(false))
		if short {
			resourceRows = shortFormatResource(resourceRows)
		}
		summaryTable.AppendHeader(generateResourceHeader(short))

		summaryTable.AppendRows(resourceRows)

		summaryTable.Render()
	}

}

func generateResourceRows(controls []resourcesresults.ResourceAssociatedControl, summaryDetails *reportsummary.SummaryDetails, resource workloadinterface.IMetadata) []table.Row {
	var rows []table.Row

	for i := range controls {
		row := make(table.Row, _resourceRowLen)

		if !controls[i].GetStatus(nil).IsFailed() {
			continue
		}

		row[resourceColumnURL] = cautils.GetControlLink(controls[i].GetID())
		paths := AssistedRemediationPathsToString(&controls[i])
		addContainerNameToAssistedRemediation(resource, &paths)
		row[resourceColumnPath] = strings.Join(paths, "\n")
		row[resourceColumnName] = controls[i].GetName()

		if c := summaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, controls[i].GetID()); c != nil {
			row[resourceColumnSeverity] = getSeverityColumn(c)
		}

		rows = append(rows, row)
	}

	return rows
}

func addContainerNameToAssistedRemediation(resource workloadinterface.IMetadata, paths *[]string) {
	for i := range *paths {
		re := regexp.MustCompile(`spec\.containers\[(\d+)]`)
		match := re.FindStringSubmatch((*paths)[i])
		if len(match) == 2 {
			index, _ := strconv.Atoi(match[1])
			wl := workloadinterface.NewWorkloadObj(resource.GetObject())
			containers, _ := wl.GetContainers()
			containerName := containers[index].Name
			(*paths)[i] = (*paths)[i] + " (" + containerName + ")"
		}
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
	for k := 0; k < l; k++ {
		if a[i][k] < a[j][k] {
			return true
		} else if a[i][k] > a[j][k] {
			return false
		}
	}
	return true
}

// TODO - deprecate once all controls support review/delete paths
func failedPathsToString(control *resourcesresults.ResourceAssociatedControl) []string {
	var paths []string

	for j := range control.ResourceAssociatedRules {
		for k := range control.ResourceAssociatedRules[j].Paths {
			if p := control.ResourceAssociatedRules[j].Paths[k].FailedPath; p != "" {
				paths = append(paths, p)
			}
		}
	}
	return paths
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
	// TODO - deprecate failedPaths once all controls support review/delete paths
	paths = appendFailedPathsIfNotInPaths(paths, failedPathsToString(control))
	return paths
}

func appendFailedPathsIfNotInPaths(paths []string, failedPaths []string) []string {
	// Create a set to efficiently check if a failed path already exists in the paths slice
	pathSet := make(map[string]struct{})
	for _, path := range paths {
		pathSet[path] = struct{}{}
	}

	// Append failed paths if they are not already present
	for _, failedPath := range failedPaths {
		if _, ok := pathSet[failedPath]; !ok {
			paths = append(paths, failedPath)
		}
	}

	return paths
}
