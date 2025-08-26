package imageprinter

import (
	"io"
	"sort"
	"strings"

	v5 "github.com/anchore/grype/grype/db/v5"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2/prettyprinter/tableprinter/utils"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
)

func renderTable(writer io.Writer, headers []string, rows [][]string) {
	table := tablewriter.NewTable(writer,
		tablewriter.WithHeaderAlignment(tw.AlignLeft),
		tablewriter.WithHeaderAutoFormat(tw.Off),
		tablewriter.WithRenderer(renderer.NewBlueprint()),
		tablewriter.WithRendition(tw.Rendition{
			Borders: tw.Border{ // Outer table borders
				Left:   tw.On,
				Right:  tw.On,
				Top:    tw.On,
				Bottom: tw.On,
			},
			Settings: tw.Settings{
				Lines: tw.Lines{ // Major internal separator lines
					ShowHeaderLine: tw.On, // Line after header
					ShowFooterLine: tw.On, // Line before footer (if footer exists)
				},
				Separators: tw.Separators{ // General row and column separators
					BetweenRows:    tw.On, // Horizontal lines between data rows
					BetweenColumns: tw.On, // Vertical lines between columns
				},
			},
		}),
	)
	table.Header(headers)
	table.Append(rows)
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
