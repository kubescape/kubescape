package clihandler

import (
	"fmt"
	"os"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/getter"
	"github.com/armosec/kubescape/opaprocessor"
	"github.com/armosec/kubescape/policyhandler"
	"github.com/armosec/kubescape/resourcehandler"
	"github.com/armosec/kubescape/resultshandling"
	"github.com/armosec/kubescape/resultshandling/printer"
	"github.com/armosec/kubescape/resultshandling/reporter"
	"github.com/armosec/opa-utils/reporthandling"
)

type CLIHandler struct {
	policyHandler *policyhandler.PolicyHandler
	scanInfo      *cautils.ScanInfo
}

var SupportedFrameworks = []string{"nsa", "mitre"}
var ValidFrameworks = strings.Join(SupportedFrameworks, ", ")

type componentInterfaces struct {
	clusterConfig   cautils.IClusterConfig
	resourceHandler resourcehandler.IResourceHandler
	report          reporter.IReport
	printerHandler  printer.IPrinter
}

func getReporter(scanInfo *cautils.ScanInfo) reporter.IReport {
	if !scanInfo.Submit {
		return reporter.NewReportMock()
	}
	if !scanInfo.FrameworkScan {
		return reporter.NewReportMock()
	}

	return reporter.NewReportEventReceiver()
}
func getInterfaces(scanInfo *cautils.ScanInfo) componentInterfaces {
	var resourceHandler resourcehandler.IResourceHandler
	var clusterConfig cautils.IClusterConfig
	var reportHandler reporter.IReport

	if !scanInfo.ScanRunningCluster() {
		k8sinterface.ConnectedToCluster = false
		clusterConfig = cautils.NewEmptyConfig()

		// load fom file
		resourceHandler = resourcehandler.NewFileResourceHandler(scanInfo.InputPatterns)

		// set mock report (do not send report)
		reportHandler = reporter.NewReportMock()
	} else {
		k8s := k8sinterface.NewKubernetesApi()
		resourceHandler = resourcehandler.NewK8sResourceHandler(k8s, scanInfo.ExcludedNamespaces)
		clusterConfig = cautils.ClusterConfigSetup(scanInfo, k8s, getter.GetArmoAPIConnector())

		// setup reporter
		reportHandler = getReporter(scanInfo)
	}

	// setup printer
	printerHandler := printer.GetPrinter(scanInfo.Format)
	printerHandler.SetWriter(scanInfo.Output)

	return componentInterfaces{
		clusterConfig:   clusterConfig,
		resourceHandler: resourceHandler,
		report:          reportHandler,
		printerHandler:  printerHandler,
	}
}

func CliSetup(scanInfo *cautils.ScanInfo) error {

	interfaces := getInterfaces(scanInfo)

	processNotification := make(chan *cautils.OPASessionObj)
	reportResults := make(chan *cautils.OPASessionObj)

	if err := interfaces.clusterConfig.SetConfig(scanInfo.Account); err != nil {
		fmt.Println(err)
	}

	cautils.ClusterName = interfaces.clusterConfig.GetClusterName()   // TODO - Deprecated
	cautils.CustomerGUID = interfaces.clusterConfig.GetCustomerGUID() // TODO - Deprecated
	interfaces.report.SetClusterName(interfaces.clusterConfig.GetClusterName())
	interfaces.report.SetCustomerGUID(interfaces.clusterConfig.GetCustomerGUID())
	// cli handler setup
	go func() {
		// policy handler setup
		policyHandler := policyhandler.NewPolicyHandler(&processNotification, interfaces.resourceHandler)
		cli := NewCLIHandler(policyHandler, scanInfo)
		if err := cli.Scan(); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}()

	// processor setup - rego run
	go func() {
		opaprocessorObj := opaprocessor.NewOPAProcessorHandler(&processNotification, &reportResults)
		opaprocessorObj.ProcessRulesListenner()
	}()

	resultsHandling := resultshandling.NewResultsHandler(&reportResults, interfaces.report, interfaces.printerHandler)
	score := resultsHandling.HandleResults(scanInfo)

	// print report url
	interfaces.clusterConfig.GenerateURL()

	adjustedFailThreshold := float32(scanInfo.FailThreshold) / 100
	if score < adjustedFailThreshold {
		return fmt.Errorf("Scan score is below threshold")
	}

	return nil
}

func NewCLIHandler(policyHandler *policyhandler.PolicyHandler, scanInfo *cautils.ScanInfo) *CLIHandler {
	return &CLIHandler{
		scanInfo:      scanInfo,
		policyHandler: policyHandler,
	}
}

func (clihandler *CLIHandler) Scan() error {
	cautils.ScanStartDisplay()
	policyNotification := &reporthandling.PolicyNotification{
		NotificationType: reporthandling.TypeExecPostureScan,
		Rules: []reporthandling.PolicyIdentifier{
			clihandler.scanInfo.PolicyIdentifier,
		},
		Designators: armotypes.PortalDesignator{},
	}
	switch policyNotification.NotificationType {
	case reporthandling.TypeExecPostureScan:
		if err := clihandler.policyHandler.HandleNotificationRequest(policyNotification, clihandler.scanInfo); err != nil {
			return err
		}

	default:
		return fmt.Errorf("notification type '%s' Unknown", policyNotification.NotificationType)
	}
	return nil
}
