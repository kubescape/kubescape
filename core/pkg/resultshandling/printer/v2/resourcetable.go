package printer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kubescape/kubescape/v2/core/cautils"
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
		fmt.Fprintf(prettyPrinter.writer, "\n"+controlCountersForResource(result.ListControlsIDs(nil))+"\n\n")

		summaryTable := tablewriter.NewWriter(prettyPrinter.writer)
		summaryTable.SetAutoWrapText(true)
		summaryTable.SetAutoMergeCells(true)
		summaryTable.SetHeader(generateResourceHeader())
		summaryTable.SetHeaderLine(true)
		summaryTable.SetRowLine(true)
		data := Matrix{}

		if raw := generateResourceRows(result.ListControls(), &opaSessionObj.Report.SummaryDetails); len(raw) > 0 {
			data = append(data, raw...)
		}
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
		row[resourceColumnPath] = strings.Join(append(failedPathsToString(&controls[i]), fixPathsToString(&controls[i])...), "\n")
		row[resourceColumnName] = controls[i].GetName()

		if c := summaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, controls[i].GetID()); c != nil {
			row[resourceColumnSeverity] = getSeverityColumn(c)
		}

		rows = append(rows, row)
	}

	return rows
}

func generateResourceHeader() []string {
	headers := make([]string, _resourceRowLen)
	headers[resourceColumnSeverity] = "Severity"
	headers[resourceColumnName] = "Control Name"
	headers[resourceColumnURL] = "Docs"
	headers[resourceColumnPath] = "Assistant Remediation"
	return headers
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

func fixPathsToString(control *resourcesresults.ResourceAssociatedControl) []string {
	var paths []string

	for j := range control.ResourceAssociatedRules {
		for k := range control.ResourceAssociatedRules[j].Paths {
			if p := control.ResourceAssociatedRules[j].Paths[k].FixPath.Path; p != "" {
				v := control.ResourceAssociatedRules[j].Paths[k].FixPath.Value
				paths = append(paths, fmt.Sprintf("%s=%s", p, v))
			}
		}
	}
	return paths
}
