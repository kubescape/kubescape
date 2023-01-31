package core

import (
	"fmt"

	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"

	"github.com/kubescape/k8s-interface/k8sinterface"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/cautils/getter"
	"github.com/kubescape/kubescape/v2/core/pkg/hostsensorutils"
	"github.com/kubescape/kubescape/v2/core/pkg/opaprocessor"
	"github.com/kubescape/kubescape/v2/core/pkg/policyhandler"
	"github.com/kubescape/kubescape/v2/core/pkg/resourcehandler"
	"github.com/kubescape/kubescape/v2/core/pkg/resourcesprioritization"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/reporter"

	"github.com/kubescape/opa-utils/resources"
)

type componentInterfaces struct {
	tenantConfig      cautils.ITenantConfig
	resourceHandler   resourcehandler.IResourceHandler
	report            reporter.IReport
	outputPrinters    []printer.IPrinter
	uiPrinter         printer.IPrinter
	hostSensorHandler hostsensorutils.IHostSensor
}

func getInterfaces(scanInfo *cautils.ScanInfo) componentInterfaces {

	// ================== setup k8s interface object ======================================
	var k8s *k8sinterface.KubernetesApi
	if scanInfo.GetScanningContext() == cautils.ContextCluster {
		k8s = getKubernetesApi()
		if k8s == nil {
			logger.L().Fatal("failed connecting to Kubernetes cluster")
		}
	}

	// ================== setup tenant object ======================================

	tenantConfig := getTenantConfig(&scanInfo.Credentials, scanInfo.KubeContext, scanInfo.CustomClusterName, k8s)

	// Set submit behavior AFTER loading tenant config
	setSubmitBehavior(scanInfo, tenantConfig)

	if scanInfo.Submit {
		// submit - Create tenant & Submit report
		if err := tenantConfig.SetTenant(); err != nil {
			logger.L().Error(err.Error())
		}

		if scanInfo.OmitRawResources {
			logger.L().Warning("omit-raw-resources flag will be ignored in submit mode")
		}
	}

	// ================== version testing ======================================

	v := cautils.NewIVersionCheckHandler()
	v.CheckLatestVersion(cautils.NewVersionCheckRequest(cautils.BuildNumber, policyIdentifierIdentities(scanInfo.PolicyIdentifier), "", cautils.ScanningContextToScanningScope(scanInfo.GetScanningContext())))

	// ================== setup host scanner object ======================================

	hostSensorHandler := getHostSensorHandler(scanInfo, k8s)
	if err := hostSensorHandler.Init(); err != nil {
		logger.L().Error("failed to init host scanner", helpers.Error(err))
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
	reportHandler := getReporter(tenantConfig, scanInfo.ScanID, scanInfo.Submit, scanInfo.FrameworkScan, scanInfo.GetScanningContext())

	// setup printers
	formats := scanInfo.Formats()

	outputPrinters := make([]printer.IPrinter, 0)
	for _, format := range formats {
		printerHandler := resultshandling.NewPrinter(format, scanInfo.FormatVersion, scanInfo.PrintAttackTree, scanInfo.VerboseMode, cautils.ViewTypes(scanInfo.View))
		printerHandler.SetWriter(scanInfo.Output)
		outputPrinters = append(outputPrinters, printerHandler)
	}

	uiPrinter := getUIPrinter(scanInfo.VerboseMode, scanInfo.FormatVersion, scanInfo.PrintAttackTree, cautils.ViewTypes(scanInfo.View))

	// ================== return interface ======================================

	return componentInterfaces{
		tenantConfig:      tenantConfig,
		resourceHandler:   resourceHandler,
		report:            reportHandler,
		outputPrinters:    outputPrinters,
		uiPrinter:         uiPrinter,
		hostSensorHandler: hostSensorHandler,
	}
}

func (ks *Kubescape) Scan(scanInfo *cautils.ScanInfo) (*resultshandling.ResultsHandler, error) {
	logger.L().Info("Kubescape scanner starting")

	// ===================== Initialization =====================
	scanInfo.Init() // initialize scan info

	interfaces := getInterfaces(scanInfo)

	cautils.ClusterName = interfaces.tenantConfig.GetContextName() // TODO - Deprecated
	cautils.CustomerGUID = interfaces.tenantConfig.GetAccountID()  // TODO - Deprecated
	interfaces.report.SetClusterName(interfaces.tenantConfig.GetContextName())
	interfaces.report.SetCustomerGUID(interfaces.tenantConfig.GetAccountID())

	downloadReleasedPolicy := getter.NewDownloadReleasedPolicy() // download config inputs from github release

	// set policy getter only after setting the customerGUID
	scanInfo.Getters.PolicyGetter = getPolicyGetter(scanInfo.UseFrom, interfaces.tenantConfig.GetTenantEmail(), scanInfo.FrameworkScan, downloadReleasedPolicy)
	scanInfo.Getters.ControlsInputsGetter = getConfigInputsGetter(scanInfo.ControlsInputs, interfaces.tenantConfig.GetAccountID(), downloadReleasedPolicy)
	scanInfo.Getters.ExceptionsGetter = getExceptionsGetter(scanInfo.UseExceptions, interfaces.tenantConfig.GetAccountID(), downloadReleasedPolicy)
	scanInfo.Getters.AttackTracksGetter = getAttackTracksGetter(scanInfo.AttackTracks, interfaces.tenantConfig.GetAccountID(), downloadReleasedPolicy)

	// TODO - list supported frameworks/controls
	if scanInfo.ScanAll {
		scanInfo.SetPolicyIdentifiers(listFrameworksNames(scanInfo.Getters.PolicyGetter), apisv1.KindFramework)
	}

	// remove host scanner components
	defer func() {
		if err := interfaces.hostSensorHandler.TearDown(); err != nil {
			logger.L().Error("failed to tear down host scanner", helpers.Error(err))
		}
	}()

	resultsHandling := resultshandling.NewResultsHandler(interfaces.report, interfaces.outputPrinters, interfaces.uiPrinter)

	// ===================== policies & resources =====================
	policyHandler := policyhandler.NewPolicyHandler(interfaces.resourceHandler)
	scanData, err := policyHandler.CollectResources(scanInfo.PolicyIdentifier, scanInfo)
	if err != nil {
		return resultsHandling, err
	}

	// ========================= opa testing =====================
	deps := resources.NewRegoDependenciesData(k8sinterface.GetK8sConfig(), interfaces.tenantConfig.GetContextName())
	reportResults := opaprocessor.NewOPAProcessor(scanData, deps)
	if err := reportResults.ProcessRulesListenner(cautils.NewProgressHandler("")); err != nil {
		// TODO - do something
		return resultsHandling, fmt.Errorf("%w", err)
	}

	// ======================== prioritization ===================

	if priotizationHandler, err := resourcesprioritization.NewResourcesPrioritizationHandler(scanInfo.Getters.AttackTracksGetter, scanInfo.PrintAttackTree); err != nil {
		logger.L().Warning("failed to get attack tracks, this may affect the scanning results", helpers.Error(err))
	} else if err := priotizationHandler.PrioritizeResources(scanData); err != nil {
		return resultsHandling, fmt.Errorf("%w", err)
	}

	// ========================= results handling =====================
	resultsHandling.SetData(scanData)

	// if resultsHandling.GetRiskScore() > float32(scanInfo.FailThreshold) {
	// 	return resultsHandling, fmt.Errorf("scan risk-score %.2f is above permitted threshold %.2f", resultsHandling.GetRiskScore(), scanInfo.FailThreshold)
	// }

	return resultsHandling, nil
}
