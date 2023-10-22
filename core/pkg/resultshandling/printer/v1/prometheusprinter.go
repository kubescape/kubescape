package printer

import (
	"context"
	"fmt"
	"os"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
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

func (p *PrometheusPrinter) SetWriter(ctx context.Context, outputFile string) {
	p.writer = printer.GetWriter(ctx, outputFile)
}

func (p *PrometheusPrinter) Score(score float32) {
	fmt.Printf("\n# Overall compliance-score (100- Excellent, 0- All failed)\nkubescape_score %d\n", cautils.Float32ToInt(score))
}

func (p *PrometheusPrinter) printResources(allResources map[string]workloadinterface.IMetadata, resourcesIDs *reporthandling.ResourcesIDs, frameworkName, controlName string) {
	p.printDetails(allResources, resourcesIDs.GetFailedResources(), frameworkName, controlName, "failed")
	p.printDetails(allResources, resourcesIDs.GetWarningResources(), frameworkName, controlName, "excluded")
	if p.verboseMode {
		p.printDetails(allResources, resourcesIDs.GetPassedResources(), frameworkName, controlName, "passed")
	}

}
func (p *PrometheusPrinter) printDetails(allResources map[string]workloadinterface.IMetadata, resourcesIDs []string, frameworkName, controlName, status string) {
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
				fmt.Fprintf(p.writer, "# Failed object from \"%s\" control \"%s\"\n", frameworkName, controlName)
				if namespace != "" {
					fmt.Fprintf(p.writer, "kubescape_object_failed_count{framework=\"%s\",control=\"%s\",namespace=\"%s\",name=\"%s\",groupVersionKind=\"%s\"} %d\n", frameworkName, controlName, namespace, name, gvk, value)
				} else {
					fmt.Fprintf(p.writer, "kubescape_object_failed_count{framework=\"%s\",control=\"%s\",name=\"%s\",groupVersionKind=\"%s\"} %d\n", frameworkName, controlName, name, gvk, value)
				}
			}
		}
	}
}

func (p *PrometheusPrinter) printReports(allResources map[string]workloadinterface.IMetadata, frameworks []reporthandling.FrameworkReport) error {
	for _, frameworkReport := range frameworks {
		for _, controlReport := range frameworkReport.ControlReports {
			if controlReport.GetNumberOfResources() == 0 {
				continue // the control did not test any resources
			}
			if controlReport.Passed() {
				continue // control passed, do not print results
			}
			fmt.Fprintf(p.writer, "# Number of resources found as part of %s control %s\nkubescape_resources_found_count{framework=\"%s\",control=\"%s\"} %d\n", frameworkReport.Name, controlReport.Name, frameworkReport.Name, controlReport.Name, controlReport.GetNumberOfResources())
			fmt.Fprintf(p.writer, "# Number of resources excluded as part of %s control %s\nkubescape_resources_excluded_count{framework=\"%s\",control=\"%s\"} %d\n", frameworkReport.Name, controlReport.Name, frameworkReport.Name, controlReport.Name, controlReport.GetNumberOfWarningResources())
			fmt.Fprintf(p.writer, "# Number of resources failed as part of %s control %s\nkubescape_resources_failed_count{framework=\"%s\",control=\"%s\"} %d\n", frameworkReport.Name, controlReport.Name, frameworkReport.Name, controlReport.Name, controlReport.GetNumberOfFailedResources())

			p.printResources(allResources, controlReport.ListResourcesIDs(), frameworkReport.Name, controlReport.Name)
		}
	}
	return nil
}

func (p *PrometheusPrinter) ActionPrint(ctx context.Context, opaSessionObj *cautils.OPASessionObj) {
	report := cautils.ReportV2ToV1(opaSessionObj)

	err := p.printReports(opaSessionObj.AllResources, report.FrameworkReports)
	if err != nil {
		logger.L().Ctx(ctx).Fatal(err.Error())
	} else {
		printer.LogOutputFile(p.writer.Name())
	}

}
