package clihandler

import (
	"fmt"
	"io/fs"
	"os"

	"github.com/armosec/armoapi-go/armotypes"
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
	"github.com/mattn/go-isatty"
)

type componentInterfaces struct {
	tenantConfig      cautils.ITenantConfig
	resourceHandler   resourcehandler.IResourceHandler
	report            reporter.IReport
	printerHandler    printer.IPrinter
	hostSensorHandler hostsensorutils.IHostSensor
}

func getInterfaces(scanInfo *cautils.ScanInfo) componentInterfaces {

	k8s := getKubernetesApi(scanInfo)

	tenantConfig := getTenantConfig(scanInfo, k8s)

	// Set submit behavior AFTER loading tenant config
	setSubmitBehavior(scanInfo, tenantConfig)

	hostSensorHandler := getHostSensorHandler(scanInfo, k8s)
	if err := hostSensorHandler.Init(); err != nil {
		errMsg := "failed to init host sensor"
		if scanInfo.VerboseMode {
			errMsg = fmt.Sprintf("%s: %v", errMsg, err)
		}
		cautils.ErrorDisplay(errMsg)
		hostSensorHandler = &hostsensorutils.HostSensorHandlerMock{}
	}
	// excluding hostsensor namespace
	if len(scanInfo.IncludeNamespaces) == 0 && hostSensorHandler.GetNamespace() != "" {
		scanInfo.ExcludedNamespaces = fmt.Sprintf("%s,%s", scanInfo.ExcludedNamespaces, hostSensorHandler.GetNamespace())
	}

	resourceHandler := getResourceHandler(scanInfo, tenantConfig, k8s, hostSensorHandler)

	// reporting behavior - setup reporter
	reportHandler := getReporter(tenantConfig, scanInfo.Submit)

	v := cautils.NewIVersionCheckHandler()
	v.CheckLatestVersion(cautils.NewVersionCheckRequest(cautils.BuildNumber, policyIdentifierNames(scanInfo.PolicyIdentifier), "", scanInfo.GetScanningEnvironment()))

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

	downloadReleasedPolicy := getter.NewDownloadReleasedPolicy() // download config inputs from github release
	// set policy getter only after setting the customerGUID
	setPolicyGetter(scanInfo, interfaces.tenantConfig.GetCustomerGUID(), downloadReleasedPolicy)
	setConfigInputsGetter(scanInfo, interfaces.tenantConfig.GetCustomerGUID(), downloadReleasedPolicy)

	defer func() {
		if err := interfaces.hostSensorHandler.TearDown(); err != nil {
			errMsg := "failed to tear down host sensor"
			if scanInfo.VerboseMode {
				errMsg = fmt.Sprintf("%s: %v", errMsg, err)
			}
			cautils.ErrorDisplay(errMsg)
		}
	}()

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

	if score > float32(scanInfo.FailThreshold) {
		return fmt.Errorf("scan risk-score %.2f is above permitted threshold %d", score, scanInfo.FailThreshold)
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
	return false

	if !isatty.IsTerminal(os.Stdin.Fd()) {
		return false
	}
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
