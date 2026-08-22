package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/kubescape/v4/core/pkg/anonymizer"
	"github.com/kubescape/kubescape/v4/core/pkg/hostsensorutils"
	"github.com/kubescape/kubescape/v4/core/pkg/opaprocessor"
	"github.com/kubescape/kubescape/v4/core/pkg/policyhandler"
	"github.com/kubescape/kubescape/v4/core/pkg/reportcrypto"
	"github.com/kubescape/kubescape/v4/core/pkg/resourcehandler"
	"github.com/kubescape/kubescape/v4/core/pkg/resourcesprioritization"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/reporter"
	"github.com/kubescape/kubescape/v4/core/pkg/scancache"
	"github.com/kubescape/kubescape/v4/pkg/imagescan"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/resources"
	"go.opentelemetry.io/otel"
	"k8s.io/client-go/kubernetes"
)

// ErrClusterConnection is returned when a cluster scan cannot reach the
// Kubernetes API server. Callers embedding Kubescape.Scan can test for it with
// errors.Is to distinguish an unreachable cluster from other scan failures.
var ErrClusterConnection = errors.New("failed connecting to Kubernetes cluster")

type componentInterfaces struct {
	tenantConfig      cautils.ITenantConfig
	resourceHandler   resourcehandler.IResourceHandler
	report            reporter.IReport
	uiPrinter         printer.IPrinter
	hostSensorHandler hostsensorutils.IHostSensor
	outputPrinters    []printer.IPrinter
	k8s               *k8sinterface.KubernetesApi
}

func getInterfaces(ctx context.Context, scanInfo *cautils.ScanInfo, policyIdentifiers []cautils.PolicyIdentifier) (componentInterfaces, error) {
	ctx, span := otel.Tracer("").Start(ctx, "setup interfaces")
	defer span.End()

	// ================== setup k8s interface object ======================================
	var k8s *k8sinterface.KubernetesApi
	var k8sClient kubernetes.Interface
	if scanInfo.GetScanningContext() == cautils.ContextCluster {
		k8s = getKubernetesApi()
		if k8s == nil {
			// Return rather than terminate: Scan already propagates this to the
			// caller, and the command layer still exits non-zero on it.
			span.RecordError(ErrClusterConnection)
			return componentInterfaces{}, ErrClusterConnection
		}
		k8sClient = k8s.KubernetesClient
	}

	// ================== setup tenant object ======================================
	tenantConfig := cautils.GetTenantConfig(ctx, scanInfo.AccountID, scanInfo.AccessKey, scanInfo.GetClusterContextName(), scanInfo.CustomClusterName, getKubernetesApi())

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
		_ = v.CheckLatestVersion(ctx, versioncheck.NewVersionCheckRequest(scanInfo.AccountID, versioncheck.BuildNumber, policyIdentifierIdentities(policyIdentifiers), "", string(scanInfo.GetScanningContext()), k8sClient))
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
		k8s:               k8s,
	}, nil
}

func GetOutputPrinters(scanInfo *cautils.ScanInfo, ctx context.Context, clusterName string) ([]printer.IPrinter, error) {
	formats := scanInfo.Formats()
	containPrettyPrinter := false
	outputPrinters := make([]printer.IPrinter, 0)
	resolvedPaths := make(map[string]string)
	// closeConfiguredPrinters closes already configured output printers upon setup failure.
	closeConfiguredPrinters := func() error {
		var closeErr error
		for _, configuredPrinter := range outputPrinters {
			if closer, ok := configuredPrinter.(interface{ CloseWriter() error }); ok {
				if err := closer.CloseWriter(); err != nil {
					closeErr = errors.Join(closeErr, err)
				}
			} else if closer, ok := configuredPrinter.(interface{ CloseWriter() }); ok {
				closer.CloseWriter()
			}
		}
		return closeErr
	}
	for _, format := range formats {
		usesPrettyPrinter, err := resultshandling.ValidatePrinter(scanInfo.ScanType, scanInfo.GetScanningContext(), format)
		if err != nil {
			return nil, errors.Join(err, closeConfiguredPrinters())
		}

		if usesPrettyPrinter && containPrettyPrinter {
			continue
		}

		if path := resolvedOutputPath(format, scanInfo.Output); path != "" {
			if existing, collision := resolvedPaths[path]; collision {
				return nil, errors.Join(fmt.Errorf("output path collision: formats %q and %q both resolve to %q; specify distinct output paths or use format-specific file extensions", existing, format, path), closeConfiguredPrinters())
			}
			resolvedPaths[path] = format
		}

		printerHandler := resultshandling.NewPrinter(ctx, format, scanInfo, clusterName)
		if err := printerHandler.SetWriter(ctx, scanInfo.Output); err != nil {
			return nil, errors.Join(fmt.Errorf("configure %q output: %w", format, err), closeConfiguredPrinters())
		}
		outputPrinters = append(outputPrinters, printerHandler)

		if usesPrettyPrinter {
			containPrettyPrinter = true
		}
	}

	return outputPrinters, nil
}

func resolvedOutputPath(format, outputFile string) string {
	return printer.ResolveOutputPath(format, outputFile)
}

// collectPolicies pins the shared handler for exactly as long as its caches are
// in use, so an idle registry sweep cannot close them during collection.
func collectPolicies(ctx context.Context, clusterName string, policyIdentifiers []cautils.PolicyIdentifier, scanInfo *cautils.ScanInfo, getters *cautils.Getters) (*cautils.OPASessionObj, error) {
	policyHandler, release := policyhandler.NewPolicyHandlerWithRelease(clusterName)
	defer release()
	return policyHandler.CollectPolicies(ctx, policyIdentifiers, scanInfo, getters)
}

// Scan runs a scan using ks.Context() as the operation's context. It is a
// compatibility wrapper around ScanContext for callers that have not
// migrated to passing their own context explicitly; see ScanContext's
// documentation for why that matters when a *Kubescape instance is reused
// or scan operations can overlap.
func (ks *Kubescape) Scan(scanInfo *cautils.ScanInfo, policyIdentifiers []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
	return ks.ScanContext(ks.Context(), scanInfo, policyIdentifiers)
}

// ScanContext runs a scan bound to the given ctx for its complete execution
// (initialization, policy/resource collection, OPA evaluation, image
// scanning, prioritization, and teardown all observe this same ctx), rather
// than re-reading ks.Context() at each stage. Callers that need a deadline
// or cancellation should derive ctx themselves (e.g. context.WithTimeout)
// and pass it in directly, instead of calling ks.SetContext beforehand:
// mutating the shared *Kubescape's context is not safe if the instance is
// reused or another operation could run concurrently against it, since a
// mid-operation ks.Context() read could observe a different deadline than
// the one that started the operation, or an already-restored/canceled one.
func (ks *Kubescape) ScanContext(ctx context.Context, scanInfo *cautils.ScanInfo, policyIdentifiers []cautils.PolicyIdentifier) (*resultshandling.ResultsHandler, error) {
	ctxInit, spanInit := otel.Tracer("").Start(ctx, "initialization")
	logger.L().Start("Kubescape scanner initializing...")

	// ===================== Initialization =====================
	policyIdentifiers = resolveDefaultScanAllPolicies(scanInfo, policyIdentifiers) // resolve the ScanAll expansion while Init can still cache its paths
	if err := scanInfo.Init(ctxInit, policyIdentifiers); err != nil {              // initialize scan info
		spanInit.End()
		return nil, err
	}
	defer scanInfo.Cleanup()
	if err := resolveClusterContext(scanInfo); err != nil {
		spanInit.End()
		return nil, err
	}

	interfaces, err := getInterfaces(ctxInit, scanInfo, policyIdentifiers)
	if err != nil {
		spanInit.End()
		return nil, err
	}
	interfaces.report.SetTenantConfig(interfaces.tenantConfig)

	// remove host scanner components
	defer func() {
		if err := interfaces.hostSensorHandler.TearDown(); err != nil {
			logger.L().Ctx(ctx).StopError("Failed to tear down host scanner", helpers.Error(err))
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
	var getters cautils.Getters
	getters.PolicyGetter, err = getPolicyGetter(ctxInit, scanInfo.UseFrom, interfaces.tenantConfig.GetAccountID(), scanInfo.FrameworkScan, downloadReleasedPolicy, airGapped)
	if err != nil {
		spanInit.End()
		return nil, err
	}
	var controlInputsFromCache bool
	getters.ControlsInputsGetter, controlInputsFromCache, err = getConfigInputsGetterForTarget(ctxInit, scanInfo.ControlsInputs, interfaces.tenantConfig.GetAccountID(), downloadReleasedPolicy, scanInfo.GetScanningContext() == cautils.ContextCluster, airGapped, interfaces.k8s)
	if err != nil {
		spanInit.End()
		return nil, err
	}
	var exceptionsFromCache bool
	getters.ExceptionsGetter, exceptionsFromCache, err = getExceptionsGetterForTarget(ctxInit, scanInfo.UseExceptions, interfaces.tenantConfig.GetAccountID(), downloadReleasedPolicy, airGapped, interfaces.k8s)
	if err != nil {
		spanInit.End()
		return nil, err
	}
	getters.AttackTracksGetter, err = getAttackTracksGetter(ctxInit, scanInfo.AttackTracks, interfaces.tenantConfig.GetAccountID(), downloadReleasedPolicy, airGapped)
	if err != nil {
		spanInit.End()
		return nil, err
	}

	if scanInfo.ScanAll {
		// Add all frameworks
		policyIdentifiers = cautils.AppendPolicyIdentifiers(policyIdentifiers, listFrameworksNames(getters.PolicyGetter), apisv1.KindFramework)

		// Add all controls
		if controls, err := getters.PolicyGetter.ListControls(); err == nil {
			controlIDs := make([]string, 0, len(controls))
			for _, control := range controls {
				controlIDs = append(controlIDs, parseControlEntry(control).ID)
			}
			policyIdentifiers = cautils.AppendPolicyIdentifiers(policyIdentifiers, controlIDs, apisv1.KindControl)
		} else {
			logger.L().Ctx(ctxInit).Warning("failed to list controls for ScanAll", helpers.Error(err))
		}
	}

	logger.L().StopSuccess("Initialized scanner")

	resultsHandling := resultshandling.NewResultsHandler(interfaces.report, interfaces.outputPrinters, interfaces.uiPrinter)

	// ===================== policies =====================
	ctxPolicies, spanPolicies := otel.Tracer("").Start(ctxInit, "policies")
	scanData, err := collectPolicies(ctxPolicies, interfaces.tenantConfig.GetContextName(), policyIdentifiers, scanInfo, &getters)
	if err != nil {
		spanInit.End()
		return resultsHandling, err
	}
	if controlInputsFromCache {
		scanData.PolicyDegradations = append(scanData.PolicyDegradations, cautils.PolicyDegradation{Component: "controlInputs", Reason: "failed to fetch from GitHub, loaded from local cache"})
	}
	if exceptionsFromCache {
		scanData.PolicyDegradations = append(scanData.PolicyDegradations, cautils.PolicyDegradation{Component: "exceptions", Reason: "failed to fetch from GitHub, loaded from local cache"})
	}
	spanPolicies.End()

	if scanInfo.DryRun {
		spanInit.End()
		resultsHandling.SetData(scanData)
		result, err := interfaces.resourceHandler.Preflight(ctxInit, scanData, scanInfo)
		if err != nil {
			return resultsHandling, err
		}
		printPreflightResult(result)
		if denied := result.Denied(); len(denied) > 0 {
			return resultsHandling, fmt.Errorf("dry-run: %d required resource type(s) cannot be listed with the current credentials", len(denied))
		}
		return resultsHandling, nil
	}

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
	ctxOpa, spanOpa := otel.Tracer("").Start(ctx, "opa testing")
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
		exceptionRecorder, shutdownRecorder := newSecurityExceptionEventRecorder()
		if shutdownRecorder != nil {
			defer shutdownRecorder()
		}
		reportResults := opaprocessor.NewOPAProcessor(scanData, deps, interfaces.tenantConfig.GetContextName(), scanInfo.ExcludedNamespaces, scanInfo.IncludeNamespaces, scanInfo.EnableRegoPrint, exceptionRecorder)
		reportResults.ControlTimeout = scanInfo.ControlTimeout
		if cacheStore := loadIncrementalCacheIfEnabled(ctxOpa, scanInfo, scanData); cacheStore != nil {
			reportResults.SetIncrementalCache(cacheStore)
			defer func() {
				if flushErr := cacheStore.Flush(); flushErr != nil {
					logger.L().Ctx(ctxOpa).Warning("failed to persist incremental scan cache", helpers.Error(flushErr))
				}
			}()
		}
		if err = reportResults.ProcessRulesListener(ctxOpa, cautils.NewProgressHandler("")); err != nil {
			logger.L().Ctx(ctxOpa).Error("failed to process rules", helpers.Error(err))
			// The eager listener finalizes its accumulated results before returning
			// an error. Streaming errors can return before that invariant holds.
			resultsHandling.SetData(scanData)
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
		if priotizationHandler, err := resourcesprioritization.NewResourcesPrioritizationHandler(ctxOpa, getters.AttackTracksGetter, scanInfo.PrintAttackTree); err != nil {
			logger.L().Ctx(ctx).Warning("failed to get attack tracks, this may affect the scanning results", helpers.Error(err))
		} else if err := priotizationHandler.PrioritizeResources(scanData); err != nil {
			return resultsHandling, fmt.Errorf("%w", err)
		}
		if isPrioritizationScanType(scanInfo.ScanType) {
			scanData.SetTopWorkloads()
		}
		spanPrioritization.End()
	}

	if scanInfo.ScanImages {
		resultsHandling.SetScanError(scanImages(scanInfo.ScanType, scanData, ctx, resultsHandling, scanInfo, interfaces.k8s))
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
				"failed to generate encryption key: %w", err,
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

func resolveClusterContext(scanInfo *cautils.ScanInfo) error {
	if scanInfo.GetScanningContext() != cautils.ContextCluster {
		return nil
	}
	if err := scanInfo.ResolveClusterContextName(); err != nil {
		return fmt.Errorf("failed to resolve Kubernetes context: %w", err)
	}
	return nil
}

func scanImages(scanType cautils.ScanTypes, scanData *cautils.OPASessionObj, ctx context.Context, resultsHandling *resultshandling.ResultsHandler, scanInfo *cautils.ScanInfo, k8sApi *k8sinterface.KubernetesApi) error {
	var scanningContext cautils.ScanningContext
	if scanInfo != nil {
		scanningContext = scanInfo.GetScanningContext()
	}
	platformOverride := ""
	if scanInfo != nil {
		platformOverride = scanInfo.ImagePlatform
	}
	imagesToScan, imageToCreds, containerErrors := collectImageScanTargets(scanType, scanData, ctx, scanningContext, k8sApi, platformOverride)
	if imagesToScan.IsEmpty() {
		return errors.Join(containerErrors...)
	}

	distCfg, installCfg, shouldUpdate, err := imagescan.NewDefaultDBConfig(scanInfo.ListingURL, scanInfo.SkipDBUpdate)
	if err != nil {
		logger.L().StopError(fmt.Sprintf("Invalid Grype database URL '%s': %v", scanInfo.ListingURL, err))
		return errors.Join(append(containerErrors, fmt.Errorf("invalid Grype database URL %q: %w", scanInfo.ListingURL, err))...)
	}
	svc, err := imagescan.NewScanServiceWithMatchersAndSources(distCfg, installCfg, scanInfo.UseDefaultMatchers, nil, shouldUpdate)
	if err != nil {
		logger.L().StopError(fmt.Sprintf("Failed to initialize image scanner: %s", err))
		return errors.Join(append(containerErrors, fmt.Errorf("failed to initialize image scanner: %w", err))...)
	}
	defer svc.Close()
	defaultCreds := registryCredentialsFromScanInfo(scanInfo)
	var jobs []ImageScanJob
	for target := range imagesToScan.Iter() {
		img := target.Image
		credsList := []imagescan.RegistryCredentials{}
		if resolvedCreds, ok := imageToCreds[img]; ok {
			sort.Slice(resolvedCreds, func(i, j int) bool {
				if resolvedCreds[i].Authority != resolvedCreds[j].Authority {
					return resolvedCreds[i].Authority < resolvedCreds[j].Authority
				}
				if resolvedCreds[i].Username != resolvedCreds[j].Username {
					return resolvedCreds[i].Username < resolvedCreds[j].Username
				}
				if resolvedCreds[i].Password != resolvedCreds[j].Password {
					return resolvedCreds[i].Password < resolvedCreds[j].Password
				}
				return resolvedCreds[i].Token < resolvedCreds[j].Token
			})
			credsList = append(credsList, resolvedCreds...)
		}

		if len(credsList) == 0 && (defaultCreds.Token != "" || defaultCreds.Username != "" || defaultCreds.Password != "") {
			credsList = append(credsList, defaultCreds)
		}

		jobs = append(jobs, ImageScanJob{
			Image:                   img,
			Platform:                target.Platform,
			SkipUnavailablePlatform: target.SkipUnavailable,
			RegistryCredentials:     credsList,
			RegistryMapping:         scanInfo.RegistryMapping,
		})
	}
	sort.Slice(jobs, func(i, j int) bool {
		if jobs[i].Image != jobs[j].Image {
			return jobs[i].Image < jobs[j].Image
		}
		return jobs[i].Platform < jobs[j].Platform
	})

	concurrency := scanInfo.ImageScanConcurrency
	if concurrency <= 0 {
		concurrency = 1
	}

	return scanImageJobsWithDiscoveryErrors(ctx, svc, concurrency, jobs, resultsHandling, containerErrors)
}

func scanImageJobsWithDiscoveryErrors(ctx context.Context, svc imageScanService, concurrency int, jobs []ImageScanJob, resultsHandling *resultshandling.ResultsHandler, discoveryErrors []error) error {
	errs := append([]error{}, discoveryErrors...)
	return errors.Join(append(errs, scanImageJobs(ctx, svc, concurrency, jobs, resultsHandling))...)
}

func scanImageJobs(ctx context.Context, svc imageScanService, concurrency int, jobs []ImageScanJob, resultsHandling *resultshandling.ResultsHandler) error {
	logger.L().Info(fmt.Sprintf("Scanning %d images concurrently with %d workers...", len(jobs), concurrency))
	orchestrator := NewImageScanOrchestrator(svc, concurrency)
	results := orchestrator.ScanImages(ctx, jobs)
	sort.Slice(results, func(i, j int) bool {
		if results[i].Image != results[j].Image {
			return results[i].Image < results[j].Image
		}
		return results[i].Platform < results[j].Platform
	})

	for _, res := range results {
		target := imageScanTarget(res.Image, res.Platform)
		if res.SkipReason != nil {
			logger.L().Warning("Skipping unavailable inferred image platform",
				helpers.String("image", target), helpers.Error(res.SkipReason))
			continue
		}
		if res.Error != nil {
			logger.L().Error("failed to scan", helpers.String("image", target), helpers.Error(res.Error))
			continue
		}
		if res.ScanData != nil {
			resultsHandling.ImageScanData = append(resultsHandling.ImageScanData, *res.ScanData)
			logger.L().Success("Done scanning", helpers.String("image", target))
		}
	}
	if agg := orchestrator.GetErrorAggregator(); agg != nil && agg.HasErrors() {
		logger.L().Warning(agg.Error())
		return agg
	}
	return nil
}

func collectImageScanTargets(scanType cautils.ScanTypes, scanData *cautils.OPASessionObj, ctx context.Context, scanningContext cautils.ScanningContext, k8sApi *k8sinterface.KubernetesApi, platformOverride string) (mapset.Set[ImageScanTarget], map[string][]imagescan.RegistryCredentials, []error) {
	imagesToScan := mapset.NewSet[ImageScanTarget]()
	imageToCreds := make(map[string][]imagescan.RegistryCredentials)
	var containerErrors []error
	nodePlatforms := buildNodePlatformIndex(scanData.AllResources)
	if scanningContext != cautils.ContextCluster {
		// imagePullSecrets belong to a live cluster target. A manifest or repository
		// may contain the same Secret name as the current kube context, but that must
		// never grant cluster credentials to an offline image scan.
		k8sApi = nil
	}

	collectWorkload := func(wl *workloadinterface.Workload) {
		images, workloadContainerErrors := getAllWorkloadImages(wl)
		for _, containerErr := range workloadContainerErrors {
			logger.L().Error("failed to collect image scan targets", helpers.Error(containerErr))
			containerErrors = append(containerErrors, containerErr)
		}
		platforms := []string{platformOverride}
		skipUnavailable := false
		if platformOverride == "" {
			selection := selectWorkloadPlatforms(wl, nodePlatforms)
			platforms = selection.platforms
			skipUnavailable = selection.skipUnavailable
			if len(platforms) == 0 {
				if selection.constrained {
					containerErrors = append(containerErrors, fmt.Errorf(
						"no observed image platform satisfies the scheduling constraints for %s", wl.GetID()))
					return
				}
				platforms = []string{""}
			}
		}
		for _, image := range images {
			if skipUnavailable {
				logger.L().Info("Scanning image across inferred platform variants",
					helpers.String("image", image), helpers.Int("platforms", len(platforms)))
			}
			for _, platform := range platforms {
				addImageScanTarget(imagesToScan, ImageScanTarget{
					Image: image, Platform: platform, SkipUnavailable: skipUnavailable,
				})
			}
			if creds, ok := resolveRegistryCredentials(ctx, k8sApi, wl, image); ok {
				found := false
				for _, c := range imageToCreds[image] {
					if c == creds {
						found = true
						break
					}
				}
				if !found {
					imageToCreds[image] = append(imageToCreds[image], creds)
				}
			}
		}
	}

	if scanType == cautils.ScanTypeWorkload {
		collectWorkload(workloadinterface.NewWorkloadObj(scanData.SingleResourceScan.GetObject()))
	} else {
		for _, workload := range scanData.AllResources {
			collectWorkload(workloadinterface.NewWorkloadObj(workload.GetObject()))
		}
	}

	return imagesToScan, imageToCreds, containerErrors
}

func addImageScanTarget(targets mapset.Set[ImageScanTarget], target ImageScanTarget) {
	for _, existing := range targets.ToSlice() {
		if existing.Image != target.Image || existing.Platform != target.Platform {
			continue
		}
		if !existing.SkipUnavailable || target.SkipUnavailable {
			return
		}
		targets.Remove(existing)
		break
	}
	targets.Add(target)
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
		ctx, svc, img, []imagescan.RegistryCredentials{creds},
		registryMapping, nil, nil, "",
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
// loadIncrementalCacheIfEnabled builds the version key from scanData's
// resolved policies (plus local controls-config bytes when set) and loads
// the incremental scan cache. Returns (nil, nil) when --incremental is off,
// so callers can call SetIncrementalCache unconditionally with the result
// only when non-nil.
func loadIncrementalCacheIfEnabled(ctx context.Context, scanInfo *cautils.ScanInfo, scanData *cautils.OPASessionObj) *scancache.Store {
	if !scanInfo.Incremental {
		return nil
	}
	policyBytes, marshalErr := json.Marshal(scanData.Policies)
	if marshalErr != nil {
		logger.L().Ctx(ctx).Warning("failed to derive incremental scan cache version, proceeding without cache", helpers.Error(marshalErr))
		return nil
	}
	allPoliciesBytes, marshalErr := json.Marshal(scanData.AllPolicies)
	if marshalErr != nil {
		logger.L().Ctx(ctx).Warning("failed to derive incremental scan cache version, proceeding without cache", helpers.Error(marshalErr))
		return nil
	}
	regoInputBytes, marshalErr := json.Marshal(scanData.RegoInputData)
	if marshalErr != nil {
		logger.L().Ctx(ctx).Warning("failed to derive incremental scan cache version, proceeding without cache", helpers.Error(marshalErr))
		return nil
	}
	versionParts := [][]byte{[]byte(scanInfo.ControlsVersion), policyBytes, allPoliciesBytes, regoInputBytes}
	if scanInfo.ControlsInputs != "" {
		if localConfig, readErr := os.ReadFile(scanInfo.ControlsInputs); readErr == nil {
			versionParts = append(versionParts, localConfig)
		}
	}
	cacheVersion := scancache.VersionKey(versionParts...)
	cacheStore, cacheErr := scancache.Load(getter.DefaultLocalStore, cacheVersion)
	if cacheErr != nil {
		logger.L().Ctx(ctx).Warning("failed to load incremental scan cache, proceeding without it", helpers.Error(cacheErr))
		return nil
	}
	return cacheStore
}

func collectAndProcessResourcesWithStreaming(ctx context.Context, resourceHandler resourcehandler.IResourceHandler, scanData *cautils.OPASessionObj, scanInfo *cautils.ScanInfo, clusterName string, excludedNamespaces string, includeNamespaces string, enableRegoPrint bool, controlTimeout time.Duration, estimatedClusterSize int) error {
	// The eager collector initializes this metadata before constructing the OPA
	// processor. Do the same here because the cloud provider is a policy input,
	// not only report metadata.
	resourcehandler.CollectClusterMetadata(ctx, resourceHandler, scanData)

	// Construct the processor before starting the producer goroutine. The
	// producer does not touch scanData's resource maps (it carries them on the
	// resident batch instead), but constructing first means the constructor's
	// reads of scanData cannot race a producer write regardless of what the
	// producer does later — the invariant is enforced by ordering rather than by
	// a comment in the resource handler.
	deps := resources.NewRegoDependenciesData(k8sinterface.GetK8sConfig(), clusterName)
	exceptionRecorder, shutdownRecorder := newSecurityExceptionEventRecorder()
	if shutdownRecorder != nil {
		defer shutdownRecorder()
	}
	reportResults := opaprocessor.NewOPAProcessor(scanData, deps, clusterName, excludedNamespaces, includeNamespaces, enableRegoPrint, exceptionRecorder)
	reportResults.ControlTimeout = controlTimeout
	if cacheStore := loadIncrementalCacheIfEnabled(ctx, scanInfo, scanData); cacheStore != nil {
		reportResults.SetIncrementalCache(cacheStore)
		defer func() {
			if flushErr := cacheStore.Flush(); flushErr != nil {
				logger.L().Ctx(ctx).Warning("failed to persist incremental scan cache", helpers.Error(flushErr))
			}
		}()
	}

	// Stream resources in batches
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	batchChan, errChan, expectedNamespaceBatches, err := resourceHandler.StreamResourcesBatches(streamCtx, scanData, scanInfo)
	if err != nil {
		return fmt.Errorf("failed to start resource streaming: %w", err)
	}
	// AllResources is still empty here — the producer goroutine fills it only
	// after the resident batch is sent — so the frozen bucketing count must
	// come from the estimate rather than the construction-time snapshot.
	reportResults.SetInitialResourceCount(estimatedClusterSize)

	// Process batches with streaming
	if err := reportResults.ProcessWithStreaming(streamCtx, batchChan, errChan, cautils.NewProgressHandler(""), expectedNamespaceBatches); err != nil {
		return fmt.Errorf("failed to process rules with streaming: %w", err)
	}

	return nil
}

func getAllWorkloadImages(wl *workloadinterface.Workload) ([]string, []error) {
	var images []string
	var containerErrors []error
	addContainerError := func(containerClass string, err error) {
		containerErrors = append(containerErrors, fmt.Errorf("failed to get %s for kind: %s, name: %s, namespace: %s: %w", containerClass, wl.GetKind(), wl.GetName(), wl.GetNamespace(), err))
	}

	if containers, err := wl.GetContainers(); err != nil {
		addContainerError("containers", err)
	} else {
		for _, c := range containers {
			if c.Image != "" {
				images = append(images, c.Image)
			}
		}
	}
	if initContainers, err := wl.GetInitContainers(); err != nil {
		addContainerError("init containers", err)
	} else {
		for _, c := range initContainers {
			if c.Image != "" {
				images = append(images, c.Image)
			}
		}
	}
	if ephemeralContainers, err := wl.GetEphemeralContainers(); err != nil {
		addContainerError("ephemeral containers", err)
	} else {
		for _, c := range ephemeralContainers {
			if c.Image != "" {
				images = append(images, c.Image)
			}
		}
	}
	return images, containerErrors
}

// printPreflightResult prints the --dry-run RBAC check to stdout.
func printPreflightResult(result *resourcehandler.PreflightResult) {
	for _, f := range result.DiscoveryFailures {
		fmt.Printf("DISCOVERY FAILED  %s: %s\n", f.GVR, f.Error)
	}

	errored := result.Errored()
	for _, c := range errored {
		fmt.Printf("CHECK FAILED  list %s: %s\n", c.GVR, c.Reason)
	}

	denied := result.Denied()
	if len(denied) == 0 && len(errored) == 0 {
		fmt.Printf("All %d required resource type(s) can be listed with the current credentials.\n", len(result.Checks))
		return
	}

	for _, c := range denied {
		// The API server's reason is what tells a user which binding to fix, so
		// print it when there is one; RBAC often answers with none.
		if c.Reason != "" {
			fmt.Printf("DENIED  list %s: %s\n", c.GVR, c.Reason)
		} else {
			fmt.Printf("DENIED  list %s\n", c.GVR)
		}
		if len(c.AffectedControls) > 0 {
			fmt.Printf("        -> %s will not evaluate\n", strings.Join(c.AffectedControls, ", "))
		}
	}

	allowed := len(result.Checks) - len(denied) - len(errored)
	fmt.Printf("\n%d/%d required resource type(s) can be listed. %d denied, %d could not be checked.\n", allowed, len(result.Checks), len(denied), len(errored))
}
