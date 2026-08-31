package printer

import (
	"fmt"
	"io"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/kubescape/kubescape/v4/core/cautils"
)

const (
	namespaceColumnName = iota
	namespaceColumnScore
	namespaceColumnFailedControls
	namespaceColumnResources
)

// printNamespaceSummaries renders the per-namespace compliance rollup as a
// table, worst-scoring namespace first (see cautils.BuildNamespaceSummaries).
func printNamespaceSummaries(writer io.Writer, summaries cautils.NamespaceSummaries) {
	if len(summaries) == 0 {
		return
	}

	t := table.NewWriter()
	t.SetOutputMirror(writer)
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: namespaceColumnName + 1, Align: text.AlignLeft},
		{Number: namespaceColumnScore + 1, Align: text.AlignCenter},
		{Number: namespaceColumnFailedControls + 1, Align: text.AlignCenter},
		{Number: namespaceColumnResources + 1, Align: text.AlignCenter},
	})
	t.AppendHeader(table.Row{"Namespace", "Compliance Score", "Failed Controls", "Resources"})

	for _, summary := range summaries {
		t.AppendRow(table.Row{
			summary.Namespace,
			fmt.Sprintf("%d%%", cautils.ComplianceScoreToInt(summary.ComplianceScore)),
			fmt.Sprintf("%d/%d", summary.FailedControls, summary.TotalControls),
			summary.ResourceCount,
		})
	}

	t.Render()
}
