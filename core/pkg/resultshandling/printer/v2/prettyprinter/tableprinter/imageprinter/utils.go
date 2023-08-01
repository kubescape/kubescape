package imageprinter

import (
	"io"
	"sort"
	"strings"

	v5 "github.com/anchore/grype/grype/db/v5"
	"github.com/fatih/color"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/olekukonko/tablewriter"
)

func renderTable(writer io.Writer, headers []string, columnAlignments []int, rows [][]string) {
	table := tablewriter.NewWriter(writer)
	table.SetHeader(headers)
	table.SetHeaderLine(true)
	table.SetColumnAlignment(columnAlignments)

	table.AppendBulk(rows)

	table.Render()
}

func generateRows(summary ImageScanSummary) [][]string {
	rows := make([][]string, 0, len(summary.CVEs))

	// sort CVEs by severity
	sort.Slice(summary.CVEs, func(i, j int) bool {
		return utils.ImageSeverityToInt(summary.CVEs[i].Severity) > utils.ImageSeverityToInt(summary.CVEs[j].Severity)
	})

	for _, cve := range summary.CVEs {
		rows = append(rows, generateRow(cve))
	}

	return rows
}

func generateRow(cve CVE) []string {
	row := make([]string, 5)
	row[imageColumnSeverity] = color.New(getColor(cve.Severity), color.Bold).Sprint(cve.Severity)
	row[imageColumnName] = cve.ID
	row[imageColumnComponent] = cve.Package
	row[imageColumnVersion] = cve.Version

	// if the CVE is fixed, show all the versions that fix it
	if cve.FixedState == string(v5.FixedState) {
		row[imageColumnFixedIn] = strings.Join(cve.FixVersions, ",")
		// if the CVE is not fixed, show the state
	} else if cve.FixedState == string(v5.WontFixState) {
		row[imageColumnFixedIn] = cve.FixedState
	}

	return row
}

func getImageScanningHeaders() []string {
	headers := make([]string, 5)
	headers[imageColumnSeverity] = "SEVERITY"
	headers[imageColumnName] = "NAME"
	headers[imageColumnComponent] = "COMPONENT"
	headers[imageColumnVersion] = "VERSION"
	headers[imageColumnFixedIn] = "FIXED IN"
	return headers
}

func getImageScanningColumnsAlignments() []int {
	return []int{tablewriter.ALIGN_CENTER, tablewriter.ALIGN_LEFT, tablewriter.ALIGN_LEFT, tablewriter.ALIGN_LEFT, tablewriter.ALIGN_LEFT}
}

func getColor(severity string) color.Attribute {
	switch severity {
	case apis.SeverityCriticalString:
		return color.FgRed
	case apis.SeverityHighString:
		return color.FgYellow
	case apis.SeverityMediumString:
		return color.FgCyan
	case apis.SeverityLowString:
		return color.FgBlue
	case apis.SeverityNegligibleString:
		return color.FgMagenta
	default:
		return color.FgWhite
	}
}
