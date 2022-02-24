package clihandler

import (
	"fmt"
	"io/fs"
	"os"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/kubescape/resultshandling/printer"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/getter"
	"github.com/armosec/kubescape/cautils/logger"
	"github.com/armosec/kubescape/cautils/logger/helpers"
	"github.com/armosec/kubescape/hostsensorutils"
	"github.com/armosec/kubescape/opaprocessor"
	"github.com/armosec/kubescape/policyhandler"
	"github.com/armosec/kubescape/resourcehandler"
	"github.com/armosec/kubescape/resultshandling"
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

	// ================== setup k8s interface object ======================================
	var k8s *k8sinterface.KubernetesApi
	if scanInfo.GetScanningEnvironment() == cautils.ScanCluster {
		k8s = getKubernetesApi()
		if k8s == nil {
			logger.L().Fatal("failed connecting to Kubernetes cluster")
		}
	}

	// ================== setup tenant object ======================================

	tenantConfig := getTenantConfig(scanInfo.Account, scanInfo.KubeContext, k8s)

	// Set submit behavior AFTER loading tenant config
	setSubmitBehavior(scanInfo, tenantConfig)

	// ================== version testing ======================================

	v := cautils.NewIVersionCheckHandler()
	v.CheckLatestVersion(cautils.NewVersionCheckRequest(cautils.BuildNumber, policyIdentifierNames(scanInfo.PolicyIdentifier), "", scanInfo.GetScanningEnvironment()))

	// ================== setup host sensor object ======================================

	hostSensorHandler := getHostSensorHandler(scanInfo, k8s)
	if err := hostSensorHandler.Init(); err != nil {
		logger.L().Error("failed to init host sensor", helpers.Error(err))
		hostSensorHandler = &hostsensorutils.HostSensorHandlerMock{}
	}
	// excluding hostsensor namespace
	if len(scanInfo.IncludeNamespaces) == 0 && hostSensorHandler.GetNamespace() != "" {
		scanInfo.ExcludedNamespaces = fmt.Sprintf("%s,%s", scanInfo.ExcludedNamespaces, hostSensorHandler.GetNamespace())
	}

	// ================== setup registry adaptors ======================================

	registryAdaptors, err := resourcehandler.NewRegistryAdaptors()
	if err != nil {
		logger.L().Error("failed to initialize registry adaptors", helpers.Error(err))
	}

	// ================== setup resource collector object ======================================

	resourceHandler := getResourceHandler(scanInfo, tenantConfig, k8s, hostSensorHandler, registryAdaptors)

	// ================== setup reporter & printer objects ======================================

	// reporting behavior - setup reporter
	reportHandler := getReporter(tenantConfig, scanInfo.Submit)

	// setup printer
	printerHandler := resultshandling.NewPrinter(scanInfo.Format, scanInfo.OutputVersion, scanInfo.VerboseMode)
	printerHandler.SetWriter(scanInfo.Output)

	// ================== return interface ======================================

	return componentInterfaces{
		tenantConfig:      tenantConfig,
		resourceHandler:   resourceHandler,
		report:            reportHandler,
		printerHandler:    printerHandler,
		hostSensorHandler: hostSensorHandler,
	}
}

func ScanCliSetup(scanInfo *cautils.ScanInfo) error {
	logger.L().Info("ARMO security scanner starting")

	interfaces := getInterfaces(scanInfo)
	// setPolicyGetter(scanInfo, interfaces.clusterConfig.GetCustomerGUID())

	processNotification := make(chan *cautils.OPASessionObj)
	reportResults := make(chan *cautils.OPASessionObj)

	cautils.ClusterName = interfaces.tenantConfig.GetClusterName() // TODO - Deprecated
	cautils.CustomerGUID = interfaces.tenantConfig.GetAccountID()  // TODO - Deprecated
	interfaces.report.SetClusterName(interfaces.tenantConfig.GetClusterName())
	interfaces.report.SetCustomerGUID(interfaces.tenantConfig.GetAccountID())

	downloadReleasedPolicy := getter.NewDownloadReleasedPolicy() // download config inputs from github release

	// set policy getter only after setting the customerGUID
	scanInfo.Getters.PolicyGetter = getPolicyGetter(scanInfo.UseFrom, interfaces.tenantConfig.GetAccountID(), scanInfo.FrameworkScan, downloadReleasedPolicy)
	scanInfo.Getters.ControlsInputsGetter = getConfigInputsGetter(scanInfo.ControlsInputs, interfaces.tenantConfig.GetAccountID(), downloadReleasedPolicy)
	scanInfo.Getters.ExceptionsGetter = getExceptionsGetter(scanInfo.UseExceptions)

	// TODO - list supported frameworks/controls
	if scanInfo.ScanAll {
		scanInfo.SetPolicyIdentifiers(listFrameworksNames(scanInfo.Getters.PolicyGetter), reporthandling.KindFramework)
	}

	//
	defer func() {
		if err := interfaces.hostSensorHandler.TearDown(); err != nil {
			logger.L().Error("failed to tear down host sensor", helpers.Error(err))
		}
	}()

	// cli handler setup
	go func() {
		// policy handler setup
		policyHandler := policyhandler.NewPolicyHandler(&processNotification, interfaces.resourceHandler)

		if err := Scan(policyHandler, scanInfo); err != nil {
			logger.L().Fatal(err.Error())
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
		Rules: scanInfo.PolicyIdentifier,
		KubescapeNotification: reporthandling.KubescapeNotification{
			Designators:      armotypes.PortalDesignator{},
			NotificationType: reporthandling.TypeExecPostureScan,
		},
	}
	switch policyNotification.KubescapeNotification.NotificationType {
	case reporthandling.TypeExecPostureScan:
		if err := policyHandler.HandleNotificationRequest(policyNotification, scanInfo); err != nil {
			return err
		}

	default:
		return fmt.Errorf("notification type '%s' Unknown", policyNotification.KubescapeNotification.NotificationType)
	}
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
			fmt.Fprintf(os.Stderr, "Would you like to scan K8s nodes? [y/N]. This is required to collect valuable data for certain controls\n")
			fmt.Fprintf(os.Stderr, "Use --enable-host-scan flag to suppress this message\n")
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
