package imageprinter

import (
	"io"
	"sort"
	"strings"

	v5 "github.com/anchore/grype/grype/db/v5"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
)

func renderTable(writer io.Writer, headers table.Row, columnAlignments []table.ColumnConfig, rows []table.Row) {
	tableWriter := table.NewWriter()
	tableWriter.SetOutputMirror(writer)
	tableWriter.AppendHeader(headers)
	tableWriter.Style().Options.SeparateHeader = true
	tableWriter.Style().Format.HeaderAlign = text.AlignLeft
	tableWriter.Style().Format.Header = text.FormatDefault
	tableWriter.SetColumnConfigs(columnAlignments)
	tableWriter.Style().Box = table.StyleBoxRounded

	tableWriter.AppendRows(rows)

	tableWriter.Render()
}

func generateRows(summary ImageScanSummary) []table.Row {
	rows := make([]table.Row, 0, len(summary.CVEs))

	// sort CVEs by severity (descending) and then by CVE ID (ascending)
	sort.Slice(summary.CVEs, func(i, j int) bool {
		if utils.ImageSeverityToInt(summary.CVEs[i].Severity) != utils.ImageSeverityToInt(summary.CVEs[j].Severity) {
			return utils.ImageSeverityToInt(summary.CVEs[i].Severity) > utils.ImageSeverityToInt(summary.CVEs[j].Severity)
		}
		return summary.CVEs[i].ID < summary.CVEs[j].ID
	})

	for _, cve := range summary.CVEs {
		rows = append(rows, generateRow(cve))
	}

	return rows
}

func generateRow(cve CVE) table.Row {
	row := make(table.Row, 6)
	row[imageColumnSeverity] = utils.GetColorForVulnerabilitySeverity(cve.Severity)(cve.Severity)
	row[imageColumnName] = cve.ID
	row[imageColumnComponent] = cve.Package
	row[imageColumnVersion] = cve.Version
	row[imageColumnImage] = cve.Image

	// if the CVE is fixed, show all the versions that fix it
	if cve.FixedState == string(v5.FixedState) {
		row[imageColumnFixedIn] = strings.Join(cve.FixVersions, ",")
		// if the CVE is not fixed, show the state
	} else if cve.FixedState == string(v5.WontFixState) {
		row[imageColumnFixedIn] = cve.FixedState
	} else {
		row[imageColumnFixedIn] = ""
	}

	return row
}

func getImageScanningHeaders() table.Row {
	headers := make(table.Row, 6)
	headers[imageColumnSeverity] = "Severity"
	headers[imageColumnName] = "Vulnerability"
	headers[imageColumnComponent] = "Component"
	headers[imageColumnVersion] = "Version"
	headers[imageColumnFixedIn] = "Fixed in"
	headers[imageColumnImage] = "Image"
	return headers
}

func getImageScanningColumnsAlignments() []table.ColumnConfig {
	return []table.ColumnConfig{
		{Number: 1, Align: text.AlignCenter},
		{Number: 2, Align: text.AlignLeft},
		{Number: 3, Align: text.AlignLeft},
		{Number: 4, Align: text.AlignLeft},
		{Number: 5, Align: text.AlignLeft},
		{Number: 6, Align: text.AlignLeft},
	}
}
