package prettyprinter

import (
	"fmt"
	"os"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/olekukonko/tablewriter"
)

func NewClusterPrinter() *MainPrinterImpl {
	printer := &MainPrinterImpl{}

	printer.CategoriesConfig = NewCategoriesConfiguration(getCommonCategoriesTableHeaders(), getCommonColumnsAlignments())

	printer.NextSteps = getClusterNextSteps()

	printer.TopXWorkloadsFunc = clusterTopXWorkloadsFunc

	printer.SetCompliancePrint(true)

	return printer
}

func clusterTopXWorkloadsFunc(writer *os.File, topXWls []reportsummary.TopWorkload) {
	for i, wl := range topXWls {
		ns := wl.Workload.GetNamespace()
		name := wl.Workload.GetName()
		kind := wl.Workload.GetKind()
		cautils.SimpleDisplay(writer, fmt.Sprintf("%d. namespace: %s, name: %s, kind: %s - '%s'\n", i+1, ns, name, kind, getWorkloadScanCommand(ns, kind, name)))
	}

	cautils.InfoTextDisplay(writer, "\n")
}

func getWorkloadScanCommand(namespace, kind, name string) string {
	return fmt.Sprintf("$ kubescape scan workload %s/%s/%s", namespace, kind, name)
}

func getClusterNextSteps() []string {
	return []string{
		"cluster scan run: '$ kubescape scan cluster'",
		"CICD setup: <link to docs>",
		"continues monitoring install helm: <docs to helm>",
	}
}

func getCommonColumnsAlignments() []int {
	return []int{tablewriter.ALIGN_LEFT, tablewriter.ALIGN_LEFT, tablewriter.ALIGN_CENTER, tablewriter.ALIGN_LEFT}
}

func getCommonCategoriesTableHeaders() []string {
	headers := make([]string, 4)
	headers[categoriesColumnSeverity] = "SEVERITY"
	headers[categoriesColumnName] = "CONTROL NAME"
	headers[categoriesColumnFailed] = "STATUS"
	headers[categoriesColumnNextSteps] = "NEXT STEPS"

	return headers
}
