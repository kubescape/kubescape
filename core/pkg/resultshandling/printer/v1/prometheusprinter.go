package printer

import (
	"fmt"
	"os"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer"
	"github.com/kubescape/opa-utils/reporthandling"
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
	prometheusPrinter.writer = printer.GetWriter(outputFile)
}

func (prometheusPrinter *PrometheusPrinter) Score(score float32) {
	fmt.Printf("\n# Overall risk-score (0- Excellent, 100- All failed)\nkubescape_score %d\n", cautils.Float32ToInt(score))
}

func (printer *PrometheusPrinter) printResources(allResources map[string]workloadinterface.IMetadata, resourcesIDs *reporthandling.ResourcesIDs, frameworkName, controlName string) {
	printer.printDetails(allResources, resourcesIDs.GetFailedResources(), frameworkName, controlName, "failed")
	printer.printDetails(allResources, resourcesIDs.GetWarningResources(), frameworkName, controlName, "excluded")
	if printer.verboseMode {
		printer.printDetails(allResources, resourcesIDs.GetPassedResources(), frameworkName, controlName, "passed")
	}

}
func (printer *PrometheusPrinter) printDetails(allResources map[string]workloadinterface.IMetadata, resourcesIDs []string, frameworkName, controlName, status string) {
	objs := make(map[string]map[string]map[string]int)
	for _, resourceID := range resourcesIDs {
		resource := allResources[resourceID]

		gvk := fmt.Sprintf("%s/%s", resource.GetApiVersion(), resource.GetKind())

		if objs[gvk] == nil {
			objs[gvk] = make(map[string]map[string]int)
		}
		if objs[gvk][resource.GetNamespace()] == nil {
			objs[gvk][resource.GetNamespace()] = make(map[string]int)
		}
		objs[gvk][resource.GetNamespace()][resource.GetName()]++
	}
	for gvk, namespaces := range objs {
		for namespace, names := range namespaces {
			for name, value := range names {
				fmt.Fprintf(printer.writer, "# Failed object from \"%s\" control \"%s\"\n", frameworkName, controlName)
				if namespace != "" {
					fmt.Fprintf(printer.writer, "kubescape_object_failed_count{framework=\"%s\",control=\"%s\",namespace=\"%s\",name=\"%s\",groupVersionKind=\"%s\"} %d\n", frameworkName, controlName, namespace, name, gvk, value)
				} else {
					fmt.Fprintf(printer.writer, "kubescape_object_failed_count{framework=\"%s\",control=\"%s\",name=\"%s\",groupVersionKind=\"%s\"} %d\n", frameworkName, controlName, name, gvk, value)
				}
			}
		}
	}
}

func (printer *PrometheusPrinter) printReports(allResources map[string]workloadinterface.IMetadata, frameworks []reporthandling.FrameworkReport) error {
	for _, frameworkReport := range frameworks {
		for _, controlReport := range frameworkReport.ControlReports {
			if controlReport.GetNumberOfResources() == 0 {
				continue // the control did not test any resources
			}
			if controlReport.Passed() {
				continue // control passed, do not print results
			}
			fmt.Fprintf(printer.writer, "# Number of resources found as part of %s control %s\nkubescape_resources_found_count{framework=\"%s\",control=\"%s\"} %d\n", frameworkReport.Name, controlReport.Name, frameworkReport.Name, controlReport.Name, controlReport.GetNumberOfResources())
			fmt.Fprintf(printer.writer, "# Number of resources excluded as part of %s control %s\nkubescape_resources_excluded_count{framework=\"%s\",control=\"%s\"} %d\n", frameworkReport.Name, controlReport.Name, frameworkReport.Name, controlReport.Name, controlReport.GetNumberOfWarningResources())
			fmt.Fprintf(printer.writer, "# Number of resources failed as part of %s control %s\nkubescape_resources_failed_count{framework=\"%s\",control=\"%s\"} %d\n", frameworkReport.Name, controlReport.Name, frameworkReport.Name, controlReport.Name, controlReport.GetNumberOfFailedResources())

			printer.printResources(allResources, controlReport.ListResourcesIDs(), frameworkReport.Name, controlReport.Name)
		}
	}
	return nil
}

func (printer *PrometheusPrinter) ActionPrint(opaSessionObj *cautils.OPASessionObj) {
	report := cautils.ReportV2ToV1(opaSessionObj)

	err := printer.printReports(opaSessionObj.AllResources, report.FrameworkReports)
	if err != nil {
		logger.L().Fatal(err.Error())
	}
}
