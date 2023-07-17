package imageprinter

import (
	"io"
	"sort"
	"strings"

	v5 "github.com/anchore/grype/grype/db/v5"
	"github.com/fatih/color"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/olekukonko/tablewriter"
)

const (
	imageColumnSeverity  = iota
	imageColumnName      = iota
	imageColumnComponent = iota
	imageColumnVersion   = iota
	imageColumnFixedIn   = iota
)

type TableWriter struct {
}

func NewTableWriter() *TableWriter {
	return &TableWriter{}
}

var _ TablePrinter = &TableWriter{}

func (tw *TableWriter) PrintImageScanningTable(writer io.Writer, summary ImageScanSummary) {
	rows := generateRows(summary)
	if len(rows) == 0 {
		return
	}

	headers := getImageScanningHeaders()
	columnAlignments := getImageScanningColumnsAlignments()

	table := tablewriter.NewWriter(writer)
	table.SetHeader(headers)
	table.SetHeaderLine(true)
	table.SetColumnAlignment(columnAlignments)

	table.AppendBulk(rows)

	table.Render()
}

func generateRows(summary ImageScanSummary) [][]string {
	rows := make([][]string, 0, len(summary.CVEs))

	sort.Slice(summary.CVEs, func(i, j int) bool {
		return utils.ImageSeverityToInt(summary.CVEs[i].Severity) > utils.ImageSeverityToInt(summary.CVEs[j].Severity)
	})

	for _, cve := range summary.CVEs {
		rows = append(rows, generateImageScanRow(cve))
	}
	return rows
}

func generateImageScanRow(cve CVE) []string {
	row := make([]string, 5)
	row[imageColumnSeverity] = color.New(utils.GetColor(utils.ImageSeverityToInt(cve.Severity)), color.Bold).Sprint(cve.Severity)
	row[imageColumnName] = cve.ID
	row[imageColumnComponent] = cve.Package
	row[imageColumnVersion] = cve.Version
	if cve.FixedState == string(v5.FixedState) {
		row[imageColumnFixedIn] = strings.Join(cve.FixVersions, "")
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
