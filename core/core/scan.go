package core

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	"github.com/kubescape/kubescape/v3/core/pkg/anonymizer"
	"github.com/kubescape/kubescape/v3/core/pkg/hostsensorutils"
	"github.com/kubescape/kubescape/v3/core/pkg/opaprocessor"
	"github.com/kubescape/kubescape/v3/core/pkg/policyhandler"
	"github.com/kubescape/kubescape/v3/core/pkg/reportcrypto"
	"github.com/kubescape/kubescape/v3/core/pkg/resourcehandler"
	"github.com/kubescape/kubescape/v3/core/pkg/resourcesprioritization"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/reporter"
	"github.com/kubescape/kubescape/v3/pkg/imagescan"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/resources"
	"go.opentelemetry.io/otel"
	"k8s.io/client-go/kubernetes"
)

type componentInterfaces struct {
	tenantConfig      cautils.ITenantConfig
	resourceHandler   resourcehandler.IResourceHandler
	report            reporter.IReport
	uiPrinter         printer.IPrinter
	hostSensorHandler hostsensorutils.IHostSensor
	outputPrinters    []printer.IPrinter
}

func getInterfaces(ctx context.Context, scanInfo *cautils.ScanInfo) (componentInterfaces, error) {
	ctx, span := otel.Tracer("").Start(ctx, "setup interfaces")
	defer span.End()

	// ================== setup k8s interface object ======================================
	var k8s *k8sinterface.KubernetesApi
	var k8sClient kubernetes.Interface
	if scanInfo.GetScanningContext() == cautils.ContextCluster {
		k8s = getKubernetesApi()
		if k8s == nil {
			logger.L().Ctx(ctx).Fatal("failed connecting to Kubernetes cluster")
		} else {
			k8sClient = k8s.KubernetesClient
		}
	}

	// ================== setup tenant object ======================================
	tenantConfig := cautils.GetTenantConfig(ctx, scanInfo.AccountID, scanInfo.AccessKey, k8sinterface.GetContextName(), scanInfo.CustomClusterName, getKubernetesApi())

	// Set submit behavior AFTER loading tenant config
	setSubmitBehavior(scanInfo, tenantConfig)

	if scanInfo.Submit.GetBool() {
		// submit - Create tenant & Submit report
		if scanInfo.OmitRawResources {
			logger.L().Ctx(ctx).Warning("omit-raw-resources flag will be ignored in submit mode")
		}
	}

	// ================== version testing ======================================
	// Skip version check in air-gapped mode (when keep-local flag is set)
	if !scanInfo.Local {
		v := versioncheck.NewIVersionCheckHandler(ctx)
		_ = v.CheckLatestVersion(ctx, versioncheck.NewVersionCheckRequest(scanInfo.AccountID, versioncheck.BuildNumber, policyIdentifierIdentities(scanInfo.PolicyIdentifier), "", string(scanInfo.GetScanningContext()), k8sClient))
	}

	// ================== setup host scanner object ======================================
	ctxHostScanner, spanHostScanner := otel.Tracer("").Start(ctx, "setup host scanner")
	hostSensorHandler := getHostSensorHandler(ctx, scanInfo, k8s)
	if err := hostSensorHandler.Init(ctxHostScanner); err != nil {
		logger.L().Ctx(ctxHostScanner).Error("failed to init host scanner", helpers.Error(err))
		hostSensorHandler = hostsensorutils.NewHostSensorHandlerMock()
		scanInfo.HostSensorEnabled.SetBool(false)
	}
	spanHostScanner.End()

	// ================== setup resource collector object ======================================

	resourceHandler := getResourceHandler(ctx, scanInfo, tenantConfig, k8s, hostSensorHandler)

	// ================== setup reporter & printer objects ======================================

	// reporting behavior - setup reporter
	reportHandler := getReporter(ctx, tenantConfig, scanInfo.ScanID, scanInfo.Submit.GetBool(), scanInfo.FrameworkScan, *scanInfo)

	// setup printers
	outputPrinters, err := GetOutputPrinters(scanInfo, ctx, tenantConfig.GetContextName())
	if err != nil {
		return componentInterfaces{}, err
	}

	uiPrinter := GetUIPrinter(ctx, scanInfo, tenantConfig.GetContextName())

	// ================== return interface ======================================

	return componentInterfaces{
		tenantConfig:      tenantConfig,
		resourceHandler:   resourceHandler,
		report:            reportHandler,
		outputPrinters:    outputPrinters,
		uiPrinter:         uiPrinter,
		hostSensorHandler: hostSensorHandler,
	}, nil
}

func GetOutputPrinters(scanInfo *cautils.ScanInfo, ctx context.Context, clusterName string) ([]printer.IPrinter, error) {
	formats := scanInfo.Formats()
	containPrettyPrinter := false
	outputPrinters := make([]printer.IPrinter, 0)
	resolvedPaths := make(map[string]string)
	for _, format := range formats {
		usesPrettyPrinter, err := resultshandling.ValidatePrinter(scanInfo.ScanType, scanInfo.GetScanningContext(), format)
		if err != nil {
			return nil, err
		}

		if usesPrettyPrinter && containPrettyPrinter {
			continue
		}

		if path := resolvedOutputPath(format, scanInfo.Output); path != "" {
			if existing, collision := resolvedPaths[path]; collision {
				return nil, fmt.Errorf("output path collision: formats %q and %q both resolve to %q; specify distinct output paths or use format-specific file extensions", existing, format, path)
			}
			resolvedPaths[path] = format
		}

		printerHandler := resultshandling.NewPrinter(ctx, format, scanInfo, clusterName)
		printerHandler.SetWriter(ctx, scanInfo.Output)
		outputPrinters = append(outputPrinters, printerHandler)

		if usesPrettyPrinter {
			containPrettyPrinter = true
		}
	}

	return outputPrinters, nil
}

func resolvedOutputPath(format, outputFile string) string {
	trimmed := strings.TrimSpace(outputFile)
	if trimmed == "" {
		return ""
	}
	ext := fileExtForFormat(format)
	fileExt := filepath.Ext(trimmed)

	if ext == printer.YamlOutputExt && fileExt == ".yml" {
		return trimmed
	}

	if ext != "" && fileExt != ext {
		return trimmed + ext
	}
	return trimmed
}

func fileExtForFormat(format string) string {
	switch format {
	case printer.JsonFormat:
		return printer.JsonOutputExt
	case printer.YamlFormat:
		return printer.YamlOutputExt
	case printer.JunitResultFormat:
		return printer.JunitOutputExt
	case printer.SARIFFormat:
		return printer.SARIFOutputExt
	case printer.GitLabSASTFormat:
		return printer.JsonOutputExt
	case printer.HtmlFormat:
		return printer.HtmlOutputExt
	case printer.PdfFormat:
		return printer.PdfOutputExt
	case printer.PrometheusFormat:
		return printer.PrometheusOutputExt
	default:
		return printer.PrettyOutputExt
	}
}

func (ks *Kubescape) Scan(scanInfo *cautils.ScanInfo) (*resultshandling.ResultsHandler, error) {
	ctxInit, spanInit := otel.Tracer("").Start(ks.Context(), "initialization")
	logger.L().Start("Kubescape scanner initializing...")

	// ===================== Initialization =====================
	scanInfo.Init(ctxInit) // initialize scan info
	defer scanInfo.Cleanup()

	interfaces, err := getInterfaces(ctxInit, scanInfo)
	if err != nil {
		spanInit.End()
		return nil, err
	}
	interfaces.report.SetTenantConfig(interfaces.tenantConfig)

	// remove host scanner components
	defer func() {
		if err := interfaces.hostSensorHandler.TearDown(); err != nil {
			logger.L().Ctx(ks.Context()).StopError("Failed to tear down host scanner", helpers.Error(err))
		}
	}()

	// Only create DownloadReleasedPolicy if not in air-gapped mode
	airGapped := isAirGappedMode(scanInfo)
	var downloadReleasedPolicy *getter.DownloadReleasedPolicy
	if airGapped {
		// In air-gapped mode (--use-from is set — the user explicitly wants to load everything
		// from local files with no network access), don't initialize the downloader to prevent
		// network access
		downloadReleasedPolicy = nil
	} else {
		downloadReleasedPolicy = getter.NewDownloadReleasedPolicyWithVersion(scanInfo.ControlsVersion) // download config inputs from github release
	}

	// set policy getter only after setting the customerGUID
	scanInfo.PolicyGetter, err = getPolicyGetter(ctxInit, scanInfo.UseFrom, interfaces.tenantConfig.GetAccountID(), scanInfo.FrameworkScan, downloadReleasedPolicy, airGapped)
	if err != nil {
		spanInit.End()
		return nil, err
	}
	var controlInputsFromCache bool
	scanInfo.ControlsInputsGetter, controlInputsFromCache, err = getConfigInputsGetter(ctxInit, scanInfo.ControlsInputs, interfaces.tenantConfig.GetAccountID(), downloadReleasedPolicy, scanInfo.GetScanningContext() == cautils.ContextCluster, airGapped)
	if err != nil {
		spanInit.End()
		return nil, err
	}
	scanInfo.ExceptionsGetter, err = getExceptionsGetter(ctxInit, scanInfo.UseExceptions, interfaces.tenantConfig.GetAccountID(), downloadReleasedPolicy, airGapped)
	if err != nil {
		spanInit.End()
		return nil, err
	}
	scanInfo.AttackTracksGetter, err = getAttackTracksGetter(ctxInit, scanInfo.AttackTracks, interfaces.tenantConfig.GetAccountID(), downloadReleasedPolicy, airGapped)
	if err != nil {
		spanInit.End()
		return nil, err
	}

	// TODO - list supported frameworks/controls
	if scanInfo.ScanAll {
		scanInfo.SetPolicyIdentifiers(listFrameworksNames(scanInfo.PolicyGetter), apisv1.KindFramework)
	}

	logger.L().StopSuccess("Initialized scanner")

	resultsHandling := resultshandling.NewResultsHandler(interfaces.report, interfaces.outputPrinters, interfaces.uiPrinter)

	// ===================== policies =====================
	ctxPolicies, spanPolicies := otel.Tracer("").Start(ctxInit, "policies")
	policyHandler := policyhandler.NewPolicyHandler(interfaces.tenantConfig.GetContextName())
	scanData, err := policyHandler.CollectPolicies(ctxPolicies, scanInfo.PolicyIdentifier, scanInfo)
	if err != nil {
		spanInit.End()
		return resultsHandling, err
	}
	if controlInputsFromCache {
		scanData.PolicyDegradations = append(scanData.PolicyDegradations, cautils.PolicyDegradation{Component: "controlInputs", Reason: "failed to fetch from GitHub, loaded from local cache"})
	}
	spanPolicies.End()

	// ===================== resources =====================
	ctxResources, spanResources := otel.Tracer("").Start(ctxInit, "resources")

	// Determine if streaming should be enabled
	enableStreaming := scanInfo.EnableStreaming
	// Snapshot the pre-scan cluster size before the streaming decision. The
	// streaming producer populates sessionObj.AllResources asynchronously, so
	// OPAProcessor cannot snapshot the resource count at construction the way
	// the non-streaming path does; the estimate stands in for it. Computing it
	// up front also covers explicit --enable-streaming on large clusters.
	var estimatedClusterSize int
	if scanInfo.GetScanningContext() == cautils.ContextCluster {
		estimatedClusterSize = estimateClusterSize(interfaces.resourceHandler, ctxResources, scanInfo)
	}
	if !enableStreaming && scanInfo.GetScanningContext() == cautils.ContextCluster {
		// Auto-enable streaming for large clusters
		enableStreaming = cautils.IsLargeCluster(estimatedClusterSize)
		if enableStreaming {
			logger.L().Ctx(ctxResources).Info("Large cluster detected, enabling resource streaming")
		}
	}

	// OPA context for both streaming and non-streaming paths
	ctxOpa, spanOpa := otel.Tracer("").Start(ks.Context(), "opa testing")
	defer spanOpa.End()

	if enableStreaming {
		// Use streaming approach for large clusters
		err = collectAndProcessResourcesWithStreaming(ctxResources, interfaces.resourceHandler, scanData, scanInfo, interfaces.tenantConfig.GetContextName(), scanInfo.ExcludedNamespaces, scanInfo.IncludeNamespaces, scanInfo.EnableRegoPrint, scanInfo.ControlTimeout, estimatedClusterSize)
	} else {
		// Use traditional approach for small clusters
		err = resourcehandler.CollectResources(ctxResources, interfaces.resourceHandler, scanData, scanInfo)
		if err != nil {
			spanInit.End()
			return resultsHandling, err
		}

		deps := resources.NewRegoDependenciesData(k8sinterface.GetK8sConfig(), interfaces.tenantConfig.GetContextName())
		var exceptionRecorder = newSecurityExceptionEventRecorder()
		reportResults := opaprocessor.NewOPAProcessor(scanData, deps, interfaces.tenantConfig.GetContextName(), scanInfo.ExcludedNamespaces, scanInfo.IncludeNamespaces, scanInfo.EnableRegoPrint, exceptionRecorder)
		reportResults.ControlTimeout = scanInfo.ControlTimeout
		if err = reportResults.ProcessRulesListener(ctxOpa, cautils.NewProgressHandler("")); err != nil {
			logger.L().Ctx(ctxOpa).Error("failed to process rules", helpers.Error(err))
			return resultsHandling, fmt.Errorf("%w", err)
		}
	}

	if err != nil {
		spanInit.End()
		return resultsHandling, err
	}
	spanResources.End()
	spanInit.End()

	// ======================== prioritization ===================
	if scanInfo.PrintAttackTree || isPrioritizationScanType(scanInfo.ScanType) {
		_, spanPrioritization := otel.Tracer("").Start(ctxOpa, "prioritization")
		if priotizationHandler, err := resourcesprioritization.NewResourcesPrioritizationHandler(ctxOpa, scanInfo.AttackTracksGetter, scanInfo.PrintAttackTree); err != nil {
			logger.L().Ctx(ks.Context()).Warning("failed to get attack tracks, this may affect the scanning results", helpers.Error(err))
		} else if err := priotizationHandler.PrioritizeResources(scanData); err != nil {
			return resultsHandling, fmt.Errorf("%w", err)
		}
		if isPrioritizationScanType(scanInfo.ScanType) {
			scanData.SetTopWorkloads()
		}
		spanPrioritization.End()
	}

	if scanInfo.ScanImages {
		scanImages(scanInfo.ScanType, scanData, ks.Context(), resultsHandling, scanInfo)
	}
	// ========================= results handling =====================
	resultsHandling.SetData(scanData)

	if scanInfo.EncryptionEnabled {

		masterKey, err := reportcrypto.GetMasterKeyFromEnv("encryption")
		if err != nil {
			return nil, err
		}

		dek, err := reportcrypto.GenerateDEK()
		if err != nil {
			for i := range masterKey {
				masterKey[i] = 0
			}

			return nil, fmt.Errorf(
				"failed to generate encryption key",
			)
		}

		err = anonymizer.ApplyEncrypted(resultsHandling, dek, masterKey)

		// best-effort memory cleanup
		for i := range dek {
			dek[i] = 0
		}

		for i := range masterKey {
			masterKey[i] = 0
		}

		if err != nil {
			return nil, fmt.Errorf(
				"failed to encrypt sensitive fields: %w",
				err,
			)
		}

	} else if scanInfo.Hide {

		if err := anonymizer.Apply(
			resultsHandling,
		); err != nil {
			return nil, fmt.Errorf(
				"failed to hide sensitive fields: %w",
				err,
			)
		}
	}

	return resultsHandling, nil
}

func scanImages(scanType cautils.ScanTypes, scanData *cautils.OPASessionObj, ctx context.Context, resultsHandling *resultshandling.ResultsHandler, scanInfo *cautils.ScanInfo) {
	imagesToScan := mapset.NewSet[string]()

	if scanType == cautils.ScanTypeWorkload {
		containers, err := workloadinterface.NewWorkloadObj(scanData.SingleResourceScan.GetObject()).GetContainers()
		if err != nil {
			logger.L().Error("failed to get containers", helpers.Error(err))
			return
		}
		for _, container := range containers {
			imagesToScan.Add(container.Image)
		}
	} else {
		for _, workload := range scanData.AllResources {
			containers, err := workloadinterface.NewWorkloadObj(workload.GetObject()).GetContainers()
			if err != nil {
				logger.L().Error(fmt.Sprintf("failed to get containers for kind: %s, name: %s, namespace: %s", workload.GetKind(), workload.GetName(), workload.GetNamespace()), helpers.Error(err))
				continue
			}
			for _, container := range containers {
				imagesToScan.Add(container.Image)
			}
		}
	}

	distCfg, installCfg, _, err := imagescan.NewDefaultDBConfig(scanInfo.ListingURL)
	if err != nil {
		logger.L().StopError(fmt.Sprintf("Invalid Grype database URL '%s': %v", scanInfo.ListingURL, err))
		return
	}
	svc, err := imagescan.NewScanServiceWithMatchers(distCfg, installCfg, scanInfo.UseDefaultMatchers)
	if err != nil {
		logger.L().StopError(fmt.Sprintf("Failed to initialize image scanner: %s", err))
		return
	}
	defer svc.Close()

	for img := range imagesToScan.Iter() {
		logger.L().Start("Scanning", helpers.String("image", img))
		if err := scanSingleImage(ctx, img, svc, resultsHandling, scanInfo.RegistryMapping, registryCredentialsFromScanInfo(scanInfo)); err != nil {
			logger.L().StopError("failed to scan", helpers.String("image", img), helpers.Error(err))
			continue
		}
		logger.L().StopSuccess("Done scanning", helpers.String("image", img))
	}
}

func registryCredentialsFromScanInfo(scanInfo *cautils.ScanInfo) imagescan.RegistryCredentials {
	if scanInfo == nil {
		return imagescan.RegistryCredentials{}
	}
	return imagescan.RegistryCredentials{
		Authority: scanInfo.RegistryAuthority,
		Username:  scanInfo.RegistryUsername,
		Password:  scanInfo.RegistryPassword,
		Token:     scanInfo.RegistryToken,
	}
}

func scanSingleImage(ctx context.Context, img string, svc imageScanService, resultsHandling *resultshandling.ResultsHandler, registryMapping map[string]string, creds imagescan.RegistryCredentials) error {

	scanResults, err := scanWithRegistryMapping(
		ctx, svc, img, creds,
		registryMapping, nil, nil,
	)
	if err != nil {
		return err
	}

	resultsHandling.ImageScanData = append(resultsHandling.ImageScanData, *scanResults)
	return nil
}

func isPrioritizationScanType(scanType cautils.ScanTypes) bool {
	return scanType == cautils.ScanTypeCluster || scanType == cautils.ScanTypeRepo
}

// isAirGappedMode returns true if the scan is configured to run in air-gapped mode,
// i.e. the user explicitly wants to load everything from local files via --use-from,
// with no network access to download the framework/policy at all. The other local-file
// flags (--controls-config, --exceptions, --attack-tracks) each have their own
// dedicated local-file-first branch in their respective getter functions in
// initutils.go and don't need to disable the network downloader entirely.
func isAirGappedMode(scanInfo *cautils.ScanInfo) bool {
	return len(scanInfo.UseFrom) > 0
}

// estimateClusterSize estimates the cluster size for determining if streaming should be enabled.
// For cluster scans it delegates to the resource handler which queries the API server
// with metadata-only LIST requests. For file-based scans it returns 0.
// Returns 0 on error so that a failed estimate falls back to the non-streaming path.
func estimateClusterSize(resourceHandler resourcehandler.IResourceHandler, ctx context.Context, scanInfo *cautils.ScanInfo) int {
	if scanInfo.GetScanningContext() != cautils.ContextCluster {
		return 0
	}

	size, err := resourceHandler.EstimateClusterSize(ctx, scanInfo)
	if err != nil {
		logger.L().Ctx(ctx).Warning("failed to estimate cluster size, falling back to non-streaming", helpers.Error(err))
		return 0
	}
	return size
}

// collectAndProcessResourcesWithStreaming collects and processes resources in
// batches so the evaluation input stays bounded on large clusters.
// estimatedClusterSize is the pre-scan cluster-size estimate the streaming
// decision was made from; the OPA processor uses it as its frozen resource
// count because sessionObj.AllResources is populated asynchronously by the
// producer goroutine.
func collectAndProcessResourcesWithStreaming(ctx context.Context, resourceHandler resourcehandler.IResourceHandler, scanData *cautils.OPASessionObj, scanInfo *cautils.ScanInfo, clusterName string, excludedNamespaces string, includeNamespaces string, enableRegoPrint bool, controlTimeout time.Duration, estimatedClusterSize int) error {
	// Construct the processor before starting the producer goroutine. The
	// producer does not touch scanData's resource maps (it carries them on the
	// resident batch instead), but constructing first means the constructor's
	// reads of scanData cannot race a producer write regardless of what the
	// producer does later — the invariant is enforced by ordering rather than by
	// a comment in the resource handler.
	deps := resources.NewRegoDependenciesData(k8sinterface.GetK8sConfig(), clusterName)
	var exceptionRecorder = newSecurityExceptionEventRecorder()
	reportResults := opaprocessor.NewOPAProcessor(scanData, deps, clusterName, excludedNamespaces, includeNamespaces, enableRegoPrint, exceptionRecorder)
	reportResults.ControlTimeout = controlTimeout

	// Stream resources in batches
	batchChan, errChan, expectedNamespaceBatches, err := resourceHandler.StreamResourcesBatches(ctx, scanData, scanInfo)
	if err != nil {
		return fmt.Errorf("failed to start resource streaming: %w", err)
	}
	// AllResources is still empty here — the producer goroutine fills it only
	// after the resident batch is sent — so the frozen bucketing count must
	// come from the estimate rather than the construction-time snapshot.
	reportResults.SetInitialResourceCount(estimatedClusterSize)

	// Process batches with streaming
	if err := reportResults.ProcessWithStreaming(ctx, batchChan, errChan, cautils.NewProgressHandler(""), expectedNamespaceBatches); err != nil {
		return fmt.Errorf("failed to process rules with streaming: %w", err)
	}

	return nil
}
