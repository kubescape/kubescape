package imageprinter

import (
	"io"
	"strings"

	v5 "github.com/anchore/grype/grype/db/v5"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/jwalton/gchalk"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
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
	hasVEX := summaryHasVEX(summary)

	SortCVEs(summary.CVEs)

	for _, cve := range summary.CVEs {
		row := generateRow(cve)
		if hasVEX {
			row = append(row, cve.VexStatus, cve.VexJustification)
		}
		rows = append(rows, row)
	}

	return rows
}

func generateRow(cve CVE) table.Row {
	row := make(table.Row, imageBaseColumns)
	row[imageColumnSeverity] = utils.GetColorForVulnerabilitySeverity(cve.Severity)(cve.Severity)
	row[imageColumnName] = cve.ID
	kev := FormatKEV(cve.KEV)
	if kev != "" {
		kev = kevColor(kev)
	}
	row[imageColumnKEV] = kev
	row[imageColumnEPSS] = FormatEPSS(cve.EPSS)
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

// kevColor matches the colour grype uses for its KEV marker.
var kevColor = gchalk.WithAnsi256(198).Bold

func summaryHasVEX(summary ImageScanSummary) bool {
	for _, cve := range summary.CVEs {
		if cve.VexStatus != "" || cve.VexJustification != "" {
			return true
		}
	}
	return false
}

func getImageScanningHeaders() table.Row {
	return getImageScanningHeadersWithVEX(false)
}

func getImageScanningHeadersWithVEX(hasVEX bool) table.Row {
	headers := make(table.Row, imageBaseColumns)
	headers[imageColumnSeverity] = "Severity"
	headers[imageColumnName] = "Vulnerability"
	headers[imageColumnKEV] = "KEV"
	headers[imageColumnEPSS] = "EPSS"
	headers[imageColumnComponent] = "Component"
	headers[imageColumnVersion] = "Version"
	headers[imageColumnFixedIn] = "Fixed in"
	headers[imageColumnImage] = "Image"
	if hasVEX {
		headers = append(headers, "VEX Status", "VEX Justification")
	}
	return headers
}

func getImageScanningColumnsAlignments() []table.ColumnConfig {
	return getImageScanningColumnsAlignmentsWithVEX(false)
}

func getImageScanningColumnsAlignmentsWithVEX(hasVEX bool) []table.ColumnConfig {
	columns := []table.ColumnConfig{
		{Number: imageColumnSeverity + 1, Align: text.AlignCenter},
		{Number: imageColumnName + 1, Align: text.AlignLeft},
		{Number: imageColumnKEV + 1, Align: text.AlignCenter},
		{Number: imageColumnEPSS + 1, Align: text.AlignRight},
		{Number: imageColumnComponent + 1, Align: text.AlignLeft},
		{Number: imageColumnVersion + 1, Align: text.AlignLeft},
		{Number: imageColumnFixedIn + 1, Align: text.AlignLeft},
		{Number: imageColumnImage + 1, Align: text.AlignLeft},
	}
	if hasVEX {
		columns = append(columns,
			table.ColumnConfig{Number: imageColumnVexStatus + 1, Align: text.AlignLeft},
			table.ColumnConfig{Number: imageColumnVexReason + 1, Align: text.AlignLeft},
		)
	}
	return columns
}
