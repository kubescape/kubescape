package printer

import (
	"errors"
	"fmt"
	"os"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/opa-utils/reporthandling"
)

type PrometheusPrinter struct {
	writer *os.File
}

func NewPrometheusPrinter() *PrometheusPrinter {
	return &PrometheusPrinter{}
}

func (prometheusPrinter *PrometheusPrinter) SetWriter(outputFile string) {
	prometheusPrinter.writer = getWriter(outputFile)
}

func (prometheusPrinter *PrometheusPrinter) Score(score float32) {
	fmt.Printf("\n# Overall score out of 100\nkubescape_score %f\n", score*100)
}

func (printer *PrometheusPrinter) printDetails(details []reporthandling.RuleResponse, frameworkName string, controlName string) error {
	objs := make(map[string]map[string]map[string]int)
	for _, ruleResponses := range details {
		for _, k8sObj := range ruleResponses.AlertObject.K8SApiObjects {
			kind, ok := k8sObj[`kind`].(string)
			if (!ok) {
				return errors.New("Found object with non string kind")
			}
			apiVersion,ok := k8sObj[`apiVersion`].(string)
			if (!ok) {
				return errors.New("Found object with non string apiVersion")
			}
			gvk := fmt.Sprintf("%s/%s",apiVersion,kind)
			metadata,ok := k8sObj[`metadata`].(map[string]interface{})
			if (!ok) {
				return errors.New("Found object with non convertable metadata")
			}
			name,ok := metadata[`name`].(string)
			if (!ok) {
				return errors.New("Found metadata with non string name")
			}
			namespace,ok := metadata[`namespace`].(string)
			if (!ok) {
				namespace = ""
			}
			if (objs[gvk] == nil) {
				objs[gvk] = make(map[string]map[string]int)
			}
			if (objs[gvk][namespace] == nil) {
				objs[gvk][namespace] = make(map[string]int)
			}
			objs[gvk][namespace][name]++
		}
	}
	for gvk, namespaces := range objs {
		for namespace, names := range namespaces {
			for name, value := range names {
				fmt.Fprintf(printer.writer, "# Failed object from %s control %s\n", frameworkName, controlName)
				if namespace != "" {
					fmt.Fprintf(printer.writer, "kubescape_object_failed_count{framework=\"%s\",control=\"%s\",namespace=\"%s\",name=\"%s\",groupVersionKind=\"%s\"} %d\n", frameworkName, controlName, namespace, name, gvk, value)
				} else {
					fmt.Fprintf(printer.writer, "kubescape_object_failed_count{framework=\"%s\",control=\"%s\",name=\"%s\",groupVersionKind=\"%s\"} %d\n", frameworkName, controlName, name, gvk, value)
				}
			}
		}
	}
	return nil
}

func (printer *PrometheusPrinter) printReports(frameworks []reporthandling.FrameworkReport) error {
	for _, framework := range frameworks {
		for _, controlReports := range framework.ControlReports {
			if len(controlReports.RuleReports[0].RuleResponses) > 0 {
				fmt.Fprintf(printer.writer, "# Number of resources found as part of %s control %s\nkubescape_resources_found_count{framework=\"%s\",control=\"%s\"} %d\n", framework.Name, controlReports.Name, framework.Name, controlReports.Name, controlReports.GetNumberOfResources())
				fmt.Fprintf(printer.writer, "# Number of resources excluded as part of %s control %s\nkubescape_resources_excluded_count{framework=\"%s\",control=\"%s\"} %d\n", framework.Name, controlReports.Name, framework.Name, controlReports.Name, controlReports.GetNumberOfWarningResources())
				fmt.Fprintf(printer.writer, "# Number of resources failed as part of %s control %s\nkubescape_resources_failed_count{framework=\"%s\",control=\"%s\"} %d\n", framework.Name, controlReports.Name, framework.Name, controlReports.Name, controlReports.GetNumberOfFailedResources())
				err := printer.printDetails(controlReports.RuleReports[0].RuleResponses, framework.Name, controlReports.Name)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (printer *PrometheusPrinter) ActionPrint(opaSessionObj *cautils.OPASessionObj) {
	err := printer.printReports(opaSessionObj.PostureReport.FrameworkReports)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
