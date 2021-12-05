package clihandler

import (
	"fmt"
	"os"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/getter"
	"github.com/armosec/kubescape/clihandler/cliinterfaces"
	"github.com/armosec/kubescape/opaprocessor"
	"github.com/armosec/kubescape/policyhandler"
	"github.com/armosec/kubescape/resourcehandler"
	"github.com/armosec/kubescape/resultshandling"
	"github.com/armosec/kubescape/resultshandling/printer"
	"github.com/armosec/kubescape/resultshandling/reporter"
	"github.com/armosec/opa-utils/reporthandling"
)

type componentInterfaces struct {
	tenantConfig    cautils.ITenantConfig
	resourceHandler resourcehandler.IResourceHandler
	report          reporter.IReport
	printerHandler  printer.IPrinter
}

func getInterfaces(scanInfo *cautils.ScanInfo) componentInterfaces {
	var resourceHandler resourcehandler.IResourceHandler
	var tenantConfig cautils.ITenantConfig

	// scanning environment
	scanningTarget := scanInfo.GetScanningEnvironment()
	switch scanningTarget {
	case cautils.ScanLocalFiles:
		k8sinterface.ConnectedToCluster = false // DEPRECATED ?

		scanInfo.Local = true // do not submit results when scanning YAML files

		// not scanning a cluster - use localConfig struct
		tenantConfig = cautils.NewLocalConfig(getter.GetArmoAPIConnector(), scanInfo.Account)

		// load resources from file
		resourceHandler = resourcehandler.NewFileResourceHandler(scanInfo.InputPatterns)

	case cautils.ScanCluster:
		k8s := k8sinterface.NewKubernetesApi() // initialize kubernetes api object

		// pull k8s resources
		resourceHandler = resourcehandler.NewK8sResourceHandler(k8s, getFieldSelector(scanInfo))
		// use clusterConfig struct
		tenantConfig = cautils.NewClusterConfig(k8s, getter.GetArmoAPIConnector(), scanInfo.Account)
	}

	// reporting behavior - setup reporter
	reportHandler := getReporter(scanInfo, tenantConfig)

	v := cautils.NewIVersionCheckHandler()
	v.CheckLatestVersion(cautils.NewVersionCheckRequest(cautils.BuildNumber, policyIdentifierNames(scanInfo.PolicyIdentifier), "", scanningTarget))

	// setup printer
	printerHandler := printer.GetPrinter(scanInfo.Format, scanInfo.VerboseMode)
	printerHandler.SetWriter(scanInfo.Output)

	return componentInterfaces{
		tenantConfig:    tenantConfig,
		resourceHandler: resourceHandler,
		report:          reportHandler,
		printerHandler:  printerHandler,
	}
}
func ScanCliSetup(scanInfo *cautils.ScanInfo) error {
	cautils.ScanStartDisplay()

	interfaces := getInterfaces(scanInfo)
	// setPolicyGetter(scanInfo, interfaces.clusterConfig.GetCustomerGUID())

	processNotification := make(chan *cautils.OPASessionObj)
	reportResults := make(chan *cautils.OPASessionObj)

	cautils.ClusterName = interfaces.tenantConfig.GetClusterName()   // TODO - Deprecated
	cautils.CustomerGUID = interfaces.tenantConfig.GetCustomerGUID() // TODO - Deprecated
	interfaces.report.SetClusterName(interfaces.tenantConfig.GetClusterName())
	interfaces.report.SetCustomerGUID(interfaces.tenantConfig.GetCustomerGUID())

	// set policy getter only after setting the customerGUID
	setPolicyGetter(scanInfo, interfaces.tenantConfig.GetCustomerGUID())

	// cli handler setup
	go func() {
		// policy handler setup
		policyHandler := policyhandler.NewPolicyHandler(&processNotification, interfaces.resourceHandler)

		if err := Scan(policyHandler, scanInfo); err != nil {
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
	interfaces.report.DisplayReportURL()

	adjustedFailThreshold := float32(scanInfo.FailThreshold) / 100
	if score < adjustedFailThreshold {
		return fmt.Errorf("Scan score is below threshold")
	}

	return nil
}

func Scan(policyHandler *policyhandler.PolicyHandler, scanInfo *cautils.ScanInfo) error {
	policyNotification := &reporthandling.PolicyNotification{
		NotificationType: reporthandling.TypeExecPostureScan,
		Rules:            scanInfo.PolicyIdentifier,
		Designators:      armotypes.PortalDesignator{},
	}
	switch policyNotification.NotificationType {
	case reporthandling.TypeExecPostureScan:
		if err := policyHandler.HandleNotificationRequest(policyNotification, scanInfo); err != nil {
			return err
		}

	default:
		return fmt.Errorf("notification type '%s' Unknown", policyNotification.NotificationType)
	}
	return nil
}

func Submit(submitInterfaces cliinterfaces.SubmitInterfaces) error {

	// list resources
	postureReport, err := submitInterfaces.SubmitObjects.SetResourcesReport()
	if err != nil {
		return err
	}
	allresources, err := submitInterfaces.SubmitObjects.ListAllResources()
	if err != nil {
		return err
	}
	// report
	if err := submitInterfaces.Reporter.ActionSendReport(&cautils.OPASessionObj{PostureReport: postureReport, AllResources: allresources}); err != nil {
		return err
	}
	fmt.Printf("\nData has been submitted successfully")
	submitInterfaces.Reporter.DisplayReportURL()

	return nil
}
