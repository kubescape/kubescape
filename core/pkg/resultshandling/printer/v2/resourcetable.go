package printer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jwalton/gchalk"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/olekukonko/tablewriter"
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
		fmt.Fprintf(prettyPrinter.writer, "\n"+prettyprinter.ControlCountersForResource(result.ListControlsIDs(nil))+"\n\n")

		summaryTable := tablewriter.NewWriter(prettyPrinter.writer)

		summaryTable.SetAutoWrapText(true)
		summaryTable.SetAutoMergeCells(true)
		summaryTable.SetHeaderLine(true)
		summaryTable.SetRowLine(true)
		summaryTable.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
		summaryTable.SetAutoFormatHeaders(false)
		summaryTable.SetUnicodeHVC(tablewriter.Regular, tablewriter.Regular, gchalk.Ansi256(238))

		resourceRows := [][]string{}
		if raw := generateResourceRows(result.ListControls(), &opaSessionObj.Report.SummaryDetails); len(raw) > 0 {
			resourceRows = append(resourceRows, raw...)
		}

		short := utils.CheckShortTerminalWidth(resourceRows, generateResourceHeader(false))
		if short {
			summaryTable.SetAutoWrapText(false)
			summaryTable.SetAutoMergeCells(false)
			resourceRows = shortFormatResource(resourceRows)
		}
		summaryTable.SetHeader(generateResourceHeader(short))

		var headerColors []tablewriter.Colors
		for range resourceRows[0] {
			headerColors = append(headerColors, tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiYellowColor})
		}
		summaryTable.SetHeaderColor(headerColors...)

		data := Matrix{}
		data = append(data, resourceRows...)
		// For control scan framework will be nil

		sort.Sort(data)
		summaryTable.AppendBulk(data)

		summaryTable.Render()
	}

}

func generateResourceRows(controls []resourcesresults.ResourceAssociatedControl, summaryDetails *reportsummary.SummaryDetails) [][]string {
	rows := [][]string{}

	for i := range controls {
		row := make([]string, _resourceRowLen)

		if !controls[i].GetStatus(nil).IsFailed() {
			continue
		}

		row[resourceColumnURL] = cautils.GetControlLink(controls[i].GetID())
		row[resourceColumnPath] = strings.Join(AssistedRemediationPathsToString(&controls[i]), "\n")
		row[resourceColumnName] = controls[i].GetName()

		if c := summaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, controls[i].GetID()); c != nil {
			row[resourceColumnSeverity] = getSeverityColumn(c)
		}

		rows = append(rows, row)
	}

	return rows
}

func generateResourceHeader(short bool) []string {
	headers := make([]string, 0)

	if short {
		headers = append(headers, "Resources")
	} else {
		headers = append(headers, []string{"Severity", "Control name", "Docs", "Assisted remediation"}...)
	}

	return headers
}

func shortFormatResource(resourceRows [][]string) [][]string {
	rows := [][]string{}
	for _, resourceRow := range resourceRows {
		rows = append(rows, []string{fmt.Sprintf("Severity"+strings.Repeat(" ", 13)+": %+v\nControl Name"+strings.Repeat(" ", 9)+": %+v\nDocs"+strings.Repeat(" ", 17)+": %+v\nAssisted Remediation"+strings.Repeat(" ", 1)+": %+v", resourceRow[resourceColumnSeverity], resourceRow[resourceColumnName], resourceRow[resourceColumnURL], strings.Replace(resourceRow[resourceColumnPath], "\n", "\n"+strings.Repeat(" ", 23), -1))})
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
