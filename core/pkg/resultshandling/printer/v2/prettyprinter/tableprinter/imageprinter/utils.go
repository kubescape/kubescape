package imageprinter

import (
	"io"
	"sort"
	"strings"

	v5 "github.com/anchore/grype/grype/db/v5"
	"github.com/jwalton/gchalk"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/olekukonko/tablewriter"
)

func renderTable(writer io.Writer, headers []string, columnAlignments []int, rows [][]string) {
	table := tablewriter.NewWriter(writer)
	table.SetHeader(headers)
	table.SetHeaderLine(true)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAutoFormatHeaders(false)
	table.SetColumnAlignment(columnAlignments)
	table.SetUnicodeHVC(tablewriter.Regular, tablewriter.Regular, gchalk.Ansi256(238))

	var headerColors []tablewriter.Colors
	for range rows[0] {
		headerColors = append(headerColors, tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiYellowColor})
	}
	table.SetHeaderColor(headerColors...)

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
	row[imageColumnSeverity] = utils.GetColorForVulnerabilitySeverity(cve.Severity)(cve.Severity)
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
	headers[imageColumnSeverity] = "Severity"
	headers[imageColumnName] = "Vulnerability"
	headers[imageColumnComponent] = "Component"
	headers[imageColumnVersion] = "Version"
	headers[imageColumnFixedIn] = "Fixed in"
	return headers
}

func getImageScanningColumnsAlignments() []int {
	return []int{tablewriter.ALIGN_CENTER, tablewriter.ALIGN_LEFT, tablewriter.ALIGN_LEFT, tablewriter.ALIGN_LEFT, tablewriter.ALIGN_LEFT}
}
