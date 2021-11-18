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
	"github.com/golang/glog"
)

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

	return reporter.NewReportEventReceiver("", "")
}

func getFieldSelector(scanInfo *cautils.ScanInfo) resourcehandler.IFieldSelector {
	if scanInfo.IncludeNamespaces != "" {
		return resourcehandler.NewIncludeSelector(scanInfo.IncludeNamespaces)
	}
	if scanInfo.ExcludedNamespaces != "" {
		return resourcehandler.NewExcludeSelector(scanInfo.ExcludedNamespaces)
	}

	return &resourcehandler.EmptySelector{}
}
func getInterfaces(scanInfo *cautils.ScanInfo) componentInterfaces {
	var resourceHandler resourcehandler.IResourceHandler
	var clusterConfig cautils.IClusterConfig
	var reportHandler reporter.IReport
	var scanningTarget string

	if !scanInfo.ScanRunningCluster() {
		k8sinterface.ConnectedToCluster = false
		clusterConfig = cautils.NewEmptyConfig()

		// load fom file
		resourceHandler = resourcehandler.NewFileResourceHandler(scanInfo.InputPatterns)

		// set mock report (do not send report)
		reportHandler = reporter.NewReportMock()
		scanningTarget = "yaml"
	} else {
		k8s := k8sinterface.NewKubernetesApi()
		resourceHandler = resourcehandler.NewK8sResourceHandler(k8s, getFieldSelector(scanInfo))
		clusterConfig = cautils.ClusterConfigSetup(scanInfo, k8s, getter.GetArmoAPIConnector())

		// setup reporter
		reportHandler = getReporter(scanInfo)
		scanningTarget = "cluster"
	}

	v := cautils.NewIVersionCheckHandler()
	v.CheckLatestVersion(cautils.NewVersionCheckRequest(cautils.BuildNumber, "", "", scanningTarget))

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
func setPolicyGetter(scanInfo *cautils.ScanInfo, customerGUID string) {
	if len(scanInfo.UseFrom) > 0 {
		//load from file
		scanInfo.PolicyGetter = getter.NewLoadPolicy(scanInfo.UseFrom)
	} else {
		if customerGUID == "" || !scanInfo.FrameworkScan {
			scanInfo.PolicyGetter = getter.NewDownloadReleasedPolicy()
		} else {
			g := getter.GetArmoAPIConnector()
			g.SetCustomerGUID(customerGUID)
			scanInfo.PolicyGetter = g
			if scanInfo.ScanAll {
				frameworks, err := g.ListCustomFrameworks(customerGUID)
				if err != nil {
					glog.Error("failed to get custom frameworks") // handle error
					return
				}
				scanInfo.SetPolicyIdentifiers(frameworks, reporthandling.KindFramework)
			}
		}
	}
}

func ScanCliSetup(scanInfo *cautils.ScanInfo) error {

	interfaces := getInterfaces(scanInfo)

	setPolicyGetter(scanInfo, interfaces.clusterConfig.GetCustomerGUID())

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
	interfaces.clusterConfig.GenerateURL()

	adjustedFailThreshold := float32(scanInfo.FailThreshold) / 100
	if score < adjustedFailThreshold {
		return fmt.Errorf("Scan score is below threshold")
	}

	return nil
}

func Scan(policyHandler *policyhandler.PolicyHandler, scanInfo *cautils.ScanInfo) error {
	cautils.ScanStartDisplay()
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

	// report
	if err := submitInterfaces.Reporter.ActionSendReport(&cautils.OPASessionObj{PostureReport: postureReport}); err != nil {
		return err
	}
	fmt.Printf("\nData has been submitted successfully")
	submitInterfaces.ClusterConfig.GenerateURL()

	return nil
}
