package printer

import (
	"fmt"
	"os"
	"strings"

	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/opa-utils/reporthandling"
)

type PrometheusPrinter struct {
	writer      *os.File
	verboseMode bool
}

func NewPrometheusPrinter(verboseMode bool) *PrometheusPrinter {
	return &PrometheusPrinter{
		verboseMode: verboseMode,
	}
}

func (prometheusPrinter *PrometheusPrinter) SetWriter(outputFile string) {
	prometheusPrinter.writer = getWriter(outputFile)
}

func (prometheusPrinter *PrometheusPrinter) Score(score float32) {
	fmt.Printf("\n# Overall score out of 100\nkubescape_score %f\n", score*100)
}

func (printer *PrometheusPrinter) printResources(allResources map[string]workloadinterface.IMetadata, resourcesIDs *reporthandling.ResourcesIDs, frameworkName, controlName string) {
	printer.printDetails(allResources, resourcesIDs.GetFailedResources(), frameworkName, controlName, "failed")
	printer.printDetails(allResources, resourcesIDs.GetWarningResources(), frameworkName, controlName, "excluded")
	if printer.verboseMode {
		printer.printDetails(allResources, resourcesIDs.GetPassedResources(), frameworkName, controlName, "passed")
	}

}
func (printer *PrometheusPrinter) printDetails(allResources map[string]workloadinterface.IMetadata, resourcesIDs []string, frameworkName, controlName, status string) {
	fmt.Fprintf(printer.writer, "# Number of resources found as part of %s control \"%s\"\nkubescape_resources_found_count{framework=\"%s\",control=\"%s\"} %d\n", status, controlName, frameworkName, controlName, len(resourcesIDs))
	for _, resourceID := range resourcesIDs {
		resource := allResources[resourceID]
		fmt.Fprintf(printer.writer, "# %s object from \"%s\" control \"%s\"\n", strings.Title(status), frameworkName, controlName)
		if resource.GetNamespace() != "" {
			fmt.Fprintf(printer.writer, "kubescape_object_%s_count{framework=\"%s\",control=\"%s\",namespace=\"%s\",name=\"%s\",groupVersionKind=\"%s\"} %d\n", status, frameworkName, controlName, resource.GetNamespace(), resource.GetName(), fmt.Sprintf("%s/%s", resource.GetApiVersion(), resource.GetKind()), 1)
		} else {
			fmt.Fprintf(printer.writer, "kubescape_object_%s_count{framework=\"%s\",control=\"%s\",name=\"%s\",groupVersionKind=\"%s\"} %d\n", status, frameworkName, controlName, resource.GetName(), fmt.Sprintf("%s/%s", resource.GetApiVersion(), resource.GetKind()), 1)
		}
	}
}

func (printer *PrometheusPrinter) printReports(allResources map[string]workloadinterface.IMetadata, frameworks []reporthandling.FrameworkReport) error {
	for _, frameworkReport := range frameworks {
		for _, controlReport := range frameworkReport.ControlReports {
			if controlReport.GetNumberOfResources() == 0 {
				continue // the control did not test any resources
			}
			printer.printResources(allResources, controlReport.ListResourcesIDs(), frameworkReport.Name, controlReport.Name)
		}
	}
	return nil
}

func (printer *PrometheusPrinter) ActionPrint(opaSessionObj *cautils.OPASessionObj) {
	err := printer.printReports(opaSessionObj.AllResources, opaSessionObj.PostureReport.FrameworkReports)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
