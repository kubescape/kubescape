package clihandler

import (
	"fmt"
	"io/fs"
	"os"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/getter"
	"github.com/armosec/kubescape/clihandler/cliinterfaces"
	"github.com/armosec/kubescape/hostsensorutils"
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
	tenantConfig      cautils.ITenantConfig
	resourceHandler   resourcehandler.IResourceHandler
	report            reporter.IReport
	printerHandler    printer.IPrinter
	hostSensorHandler hostsensorutils.IHostSensor
}

func initHostSensor(scanInfo *cautils.ScanInfo, k8s *k8sinterface.KubernetesApi) hostsensorutils.IHostSensor {

	hasHostSensorControls := true
	// we need to determined which controls needs host sensor
	if scanInfo.HostSensor.Get() == nil && hasHostSensorControls {
		scanInfo.HostSensor.SetBool(askUserForHostSensor())
	}
	if hostSensorVal := scanInfo.HostSensor.Get(); hostSensorVal != nil && *hostSensorVal {
		hostSensorHandler, err := hostsensorutils.NewHostSensorHandler(k8s)
		if err != nil {
			glog.Errorf("failed to create host sensor: %v", err)
			return &hostsensorutils.HostSensorHandlerMock{}
		}
		return hostSensorHandler
	}
	return &hostsensorutils.HostSensorHandlerMock{}
}

func getInterfaces(scanInfo *cautils.ScanInfo) componentInterfaces {
	var resourceHandler resourcehandler.IResourceHandler
	var hostSensorHandler hostsensorutils.IHostSensor
	var tenantConfig cautils.ITenantConfig

	hostSensorHandler = &hostsensorutils.HostSensorHandlerMock{}
	// scanning environment
	scanningTarget := scanInfo.GetScanningEnvironment()
	switch scanningTarget {
	case cautils.ScanLocalFiles:
		k8sinterface.ConnectedToCluster = false // DEPRECATED ?
		scanInfo.Local = true                   // do not submit results when scanning YAML files

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
		hostSensorHandler = initHostSensor(scanInfo, k8s)
	}
	// reporting behavior - setup reporter
	reportHandler := getReporter(scanInfo, tenantConfig)

	v := cautils.NewIVersionCheckHandler()
	v.CheckLatestVersion(cautils.NewVersionCheckRequest(cautils.BuildNumber, policyIdentifierNames(scanInfo.PolicyIdentifier), "", scanningTarget))

	// setup printer
	printerHandler := printer.GetPrinter(scanInfo.Format, scanInfo.VerboseMode)
	printerHandler.SetWriter(scanInfo.Output)

	return componentInterfaces{
		tenantConfig:      tenantConfig,
		resourceHandler:   resourceHandler,
		report:            reportHandler,
		printerHandler:    printerHandler,
		hostSensorHandler: hostSensorHandler,
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

	if err := interfaces.hostSensorHandler.Init(); err != nil {
		errMsg := "failed to init host sensor"
		if scanInfo.VerboseMode {
			errMsg = fmt.Sprintf("%s: %v", errMsg, err)
		}
		cautils.ErrorDisplay(errMsg)
	} else if len(scanInfo.IncludeNamespaces) == 0 && interfaces.hostSensorHandler.GetNamespace() != "" {
		scanInfo.ExcludedNamespaces = fmt.Sprintf("%s,%s", scanInfo.ExcludedNamespaces, interfaces.hostSensorHandler)
		defer func() {
			if err := interfaces.hostSensorHandler.TearDown(); err != nil {
				errMsg := "failed to tear down host sensor"
				if scanInfo.VerboseMode {
					errMsg = fmt.Sprintf("%s: %v", errMsg, err)
				}
				cautils.ErrorDisplay(errMsg)
			}
		}()
	}

	// set policy getter only after setting the customerGUID
	setPolicyGetter(scanInfo, interfaces.tenantConfig.GetCustomerGUID())

	// cli handler setup
	go func() {
		// policy handler setup
		policyHandler := policyhandler.NewPolicyHandler(&processNotification, interfaces.resourceHandler, interfaces.hostSensorHandler)

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

func askUserForHostSensor() bool {
	if ssss, err := os.Stdin.Stat(); err == nil {
		// fmt.Printf("Found stdin type: %s\n", ssss.Mode().Type())
		if ssss.Mode().Type()&(fs.ModeDevice|fs.ModeCharDevice) > 0 { //has TTY
			fmt.Printf("Would you like to scan K8s nodes? [y/N]. This is required to collect valuable data for certain controls\n")
			fmt.Printf("Use --enable-host-scan flag to suppress this message\n")
			var b []byte = make([]byte, 1)
			if n, err := os.Stdin.Read(b); err == nil {
				if n > 0 && len(b) > 0 && (b[0] == 'y' || b[0] == 'Y') {
					return true
				}
			}
		}
	}
	return false
}
