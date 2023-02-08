package core

import (
	"context"
	"fmt"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
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
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"go.opentelemetry.io/otel"

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

func getInterfaces(ctx context.Context, scanInfo *cautils.ScanInfo) componentInterfaces {
	ctx, span := otel.Tracer("").Start(ctx, "getInterfaces")
	defer span.End()

	// ================== setup k8s interface object ======================================
	var k8s *k8sinterface.KubernetesApi
	if scanInfo.GetScanningContext() == cautils.ContextCluster {
		k8s = getKubernetesApi()
		if k8s == nil {
			logger.L().Ctx(ctx).Fatal("failed connecting to Kubernetes cluster")
		}
	}

	// ================== setup tenant object ======================================
	ctxTenant, spanTenant := otel.Tracer("").Start(ctx, "setup tenant")
	tenantConfig := getTenantConfig(&scanInfo.Credentials, k8sinterface.GetContextName(), scanInfo.CustomClusterName, k8s)

	// Set submit behavior AFTER loading tenant config
	setSubmitBehavior(scanInfo, tenantConfig)

	if scanInfo.Submit {
		// submit - Create tenant & Submit report
		if err := tenantConfig.SetTenant(); err != nil {
			logger.L().Ctx(ctxTenant).Error(err.Error())
		}

		if scanInfo.OmitRawResources {
			logger.L().Ctx(ctx).Warning("omit-raw-resources flag will be ignored in submit mode")
		}
	}
	spanTenant.End()

	// ================== version testing ======================================

	v := cautils.NewIVersionCheckHandler(ctx)
	v.CheckLatestVersion(ctx, cautils.NewVersionCheckRequest(cautils.BuildNumber, policyIdentifierIdentities(scanInfo.PolicyIdentifier), "", cautils.ScanningContextToScanningScope(scanInfo.GetScanningContext())))

	// ================== setup host scanner object ======================================
	ctxHostScanner, spanHostScanner := otel.Tracer("").Start(ctx, "setup host scanner")
	hostSensorHandler := getHostSensorHandler(ctx, scanInfo, k8s)
	if err := hostSensorHandler.Init(ctxHostScanner); err != nil {
		logger.L().Ctx(ctxHostScanner).Error("failed to init host scanner", helpers.Error(err))
		hostSensorHandler = &hostsensorutils.HostSensorHandlerMock{}
	}
	spanHostScanner.End()

	// ================== setup registry adaptors ======================================

	registryAdaptors, err := resourcehandler.NewRegistryAdaptors()
	if err != nil {
		logger.L().Ctx(ctx).Error("failed to initialize registry adaptors", helpers.Error(err))
	}

	// ================== setup resource collector object ======================================

	resourceHandler := getResourceHandler(ctx, scanInfo, tenantConfig, k8s, hostSensorHandler, registryAdaptors)

	// ================== setup reporter & printer objects ======================================

	// reporting behavior - setup reporter
	reportHandler := getReporter(ctx, tenantConfig, scanInfo.ScanID, scanInfo.Submit, scanInfo.FrameworkScan, scanInfo.GetScanningContext())

	// setup printers
	formats := scanInfo.Formats()

	outputPrinters := make([]printer.IPrinter, 0)
	for _, format := range formats {
		printerHandler := resultshandling.NewPrinter(ctx, format, scanInfo.FormatVersion, scanInfo.PrintAttackTree, scanInfo.VerboseMode, cautils.ViewTypes(scanInfo.View))
		printerHandler.SetWriter(ctx, scanInfo.Output)
		outputPrinters = append(outputPrinters, printerHandler)
	}

	uiPrinter := getUIPrinter(ctx, scanInfo.VerboseMode, scanInfo.FormatVersion, scanInfo.PrintAttackTree, cautils.ViewTypes(scanInfo.View))

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

func (ks *Kubescape) Scan(ctx context.Context, scanInfo *cautils.ScanInfo) (*resultshandling.ResultsHandler, error) {
	ctx, spanScan := otel.Tracer("").Start(ctx, "kubescape.Scan")
	defer spanScan.End()
	logger.L().Info("Kubescape scanner starting")

	// ===================== Initialization =====================
	ctxInit, spanInit := otel.Tracer("").Start(ctx, "initialization")
	scanInfo.Init(ctxInit) // initialize scan info

	interfaces := getInterfaces(ctxInit, scanInfo)

	cautils.ClusterName = interfaces.tenantConfig.GetContextName() // TODO - Deprecated
	cautils.CustomerGUID = interfaces.tenantConfig.GetAccountID()  // TODO - Deprecated
	interfaces.report.SetClusterName(interfaces.tenantConfig.GetContextName())
	interfaces.report.SetCustomerGUID(interfaces.tenantConfig.GetAccountID())

	downloadReleasedPolicy := getter.NewDownloadReleasedPolicy() // download config inputs from github release

	// set policy getter only after setting the customerGUID
	scanInfo.Getters.PolicyGetter = getPolicyGetter(ctx, scanInfo.UseFrom, interfaces.tenantConfig.GetTenantEmail(), scanInfo.FrameworkScan, downloadReleasedPolicy)
	scanInfo.Getters.ControlsInputsGetter = getConfigInputsGetter(ctx, scanInfo.ControlsInputs, interfaces.tenantConfig.GetAccountID(), downloadReleasedPolicy)
	scanInfo.Getters.ExceptionsGetter = getExceptionsGetter(ctx, scanInfo.UseExceptions, interfaces.tenantConfig.GetAccountID(), downloadReleasedPolicy)
	scanInfo.Getters.AttackTracksGetter = getAttackTracksGetter(ctx, scanInfo.AttackTracks, interfaces.tenantConfig.GetAccountID(), downloadReleasedPolicy)

	// TODO - list supported frameworks/controls
	if scanInfo.ScanAll {
		scanInfo.SetPolicyIdentifiers(listFrameworksNames(scanInfo.Getters.PolicyGetter), apisv1.KindFramework)
	}

	// remove host scanner components
	defer func() {
		if err := interfaces.hostSensorHandler.TearDown(); err != nil {
			logger.L().Ctx(ctxInit).Error("failed to tear down host scanner", helpers.Error(err))
		}
	}()

	resultsHandling := resultshandling.NewResultsHandler(interfaces.report, interfaces.outputPrinters, interfaces.uiPrinter)
	spanInit.End()

	// ===================== policies & resources =====================
	ctxPolicies, spanPolicies := otel.Tracer("").Start(ctx, "policies & resources")
	policyHandler := policyhandler.NewPolicyHandler(interfaces.resourceHandler)
	scanData, err := policyHandler.CollectResources(ctxPolicies, scanInfo.PolicyIdentifier, scanInfo)
	if err != nil {
		return resultsHandling, err
	}
	spanPolicies.End()

	// ========================= opa testing =====================
	ctxOpa, spanOpa := otel.Tracer("").Start(ctx, "opa testing")
	deps := resources.NewRegoDependenciesData(k8sinterface.GetK8sConfig(), interfaces.tenantConfig.GetContextName())
	reportResults := opaprocessor.NewOPAProcessor(scanData, deps)
	if err := reportResults.ProcessRulesListenner(ctxOpa, cautils.NewProgressHandler("")); err != nil {
		// TODO - do something
		return resultsHandling, fmt.Errorf("%w", err)
	}
	spanOpa.End()

	// ======================== prioritization ===================
	_, spanPrioritization := otel.Tracer("").Start(ctx, "prioritization")
	if priotizationHandler, err := resourcesprioritization.NewResourcesPrioritizationHandler(ctx, scanInfo.Getters.AttackTracksGetter, scanInfo.PrintAttackTree); err != nil {
		logger.L().Ctx(ctx).Warning("failed to get attack tracks, this may affect the scanning results", helpers.Error(err))
	} else if err := priotizationHandler.PrioritizeResources(scanData); err != nil {
		return resultsHandling, fmt.Errorf("%w", err)
	}
	spanPrioritization.End()

	// ========================= results handling =====================
	resultsHandling.SetData(scanData)

	// if resultsHandling.GetRiskScore() > float32(scanInfo.FailThreshold) {
	// 	return resultsHandling, fmt.Errorf("scan risk-score %.2f is above permitted threshold %.2f", resultsHandling.GetRiskScore(), scanInfo.FailThreshold)
	// }

	return resultsHandling, nil
}
