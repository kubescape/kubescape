package prettyprinter

import (
	"fmt"
	"os"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
)

func NewRepoPrinter() *MainPrinterImpl {
	printer := &MainPrinterImpl{}

	printer.CategoriesConfig = NewCategoriesConfiguration(getCommonCategoriesTableHeaders(), getCommonColumnsAlignments())

	printer.NextSteps = getRepoNextSteps()

	printer.TopXWorkloadsFunc = repoTopXWorkloadsFunc

	return printer
}

func repoTopXWorkloadsFunc(writer *os.File, topXWls []reportsummary.TopWorkload) {
	for i, wl := range topXWls {
		ns := wl.Workload.GetNamespace()
		name := wl.Workload.GetName()
		kind := wl.Workload.GetKind()
		cmdPrefix := getWorkloadPrefixForCmd(ns, kind, name)
		cautils.SimpleDisplay(writer, fmt.Sprintf("%d. %s - '%s'\n", i+1, cmdPrefix, getRepoWorkloadScanCommand(ns, kind, name, wl.ResourceSource)))
	}

	cautils.InfoTextDisplay(writer, "\n")
}

func getRepoWorkloadScanCommand(ns, kind, name string, source reporthandling.Source) string {
	cmd := fmt.Sprintf("$ kubescape scan workload %s/%s/%s", ns, kind, name)
	if ns == "" {
		cmd = fmt.Sprintf("$ kubescape scan workload %s/%s", kind, name)
	}
	if source.FileType == "Helm" {
		return fmt.Sprintf("%s --chart-path=%s", cmd, source.RelativePath)

	} else {
		return fmt.Sprintf("%s --file-path=%s", cmd, source.RelativePath)
	}
}

func getRepoNextSteps() []string {
	return []string{
		"cluster scan run: '$ kubescape scan cluster'",
		"CICD setup: <link to docs>",
		"continue monitoring install helm: <docs to helm>",
	}
}
