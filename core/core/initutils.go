package core

import (
	"context"
	"errors"
	"os"

	"github.com/google/uuid"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	"github.com/kubescape/kubescape/v3/core/pkg/hostsensorutils"
	"github.com/kubescape/kubescape/v3/core/pkg/resourcehandler"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer"
	printerv2 "github.com/kubescape/kubescape/v3/core/pkg/resultshandling/printer/v2"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/reporter"
	reporterv2 "github.com/kubescape/kubescape/v3/core/pkg/resultshandling/reporter/v2"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/rbac-utils/rbacscanner"
	"go.opentelemetry.io/otel"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// getKubernetesApi
func getKubernetesApi() *k8sinterface.KubernetesApi {
	if !k8sinterface.IsConnectedToCluster() {
		return nil
	}
	return k8sinterface.NewKubernetesApi()
}

func getExceptionsK8sClient(ctx context.Context) client.Client {
	if !k8sinterface.IsConnectedToCluster() {
		return nil
	}
	config := k8sinterface.GetK8sConfig()
	if config == nil {
		return nil
	}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		logger.L().Ctx(ctx).Warning("failed to add corev1 scheme", helpers.Error(err))
		return nil
	}
	k8sClient, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		logger.L().Ctx(ctx).Warning("failed to create controller-runtime client", helpers.Error(err))
		return nil
	}
	return k8sClient
}

func getExceptionsGetter(ctx context.Context, useExceptions string, accountID string, downloadReleasedPolicy *getter.DownloadReleasedPolicy, airGapped bool) (getter.IExceptionsGetter, error) {
	var primary getter.IExceptionsGetter

	if useExceptions != "" {
		// load exceptions from file
		primary = getter.NewLoadPolicy([]string{useExceptions})
		k8sClient := getExceptionsK8sClient(ctx)
		return getter.NewMergedExceptionsGetter(primary, getter.NewCRDExceptionsGetter(k8sClient)), nil
	}
	if airGapped {
		primary = getter.NewLoadPolicy([]string{getter.GetDefaultPath(cautils.LocalExceptionsFilename)})
		k8sClient := getExceptionsK8sClient(ctx)
		return getter.NewMergedExceptionsGetter(primary, getter.NewCRDExceptionsGetter(k8sClient)), nil
	}
	if accountID != "" {
		if downloadReleasedPolicy != nil && downloadReleasedPolicy.IsVersionPinned() {
			logger.L().Ctx(ctx).Warning("--controls-version is ignored for exceptions when an account ID is set; exceptions are downloaded from the Kubescape Cloud backend")
		}
		// download exceptions from Kubescape Cloud backend
		primary = getter.GetKSCloudAPIAdapter()
		k8sClient := getExceptionsK8sClient(ctx)
		return getter.NewMergedExceptionsGetter(primary, getter.NewCRDExceptionsGetter(k8sClient)), nil
	}
	// download exceptions from GitHub
	if downloadReleasedPolicy == nil {
		downloadReleasedPolicy = getter.NewDownloadReleasedPolicy()
	}
	if fallback, err := downloadReleasedPolicy.SetRegoObjectsWithFallback(); err != nil {
		// pinned version: hard error, do not silently serve cached exceptions
		return nil, err
	} else if fallback { // if failed to pull exceptions, fallback to cache
		logger.L().Ctx(ctx).Warning("failed to get exceptions from github release, loading exceptions from cache")
		primary = getter.NewLoadPolicy([]string{getter.GetDefaultPath(cautils.LocalExceptionsFilename)})
		k8sClient := getExceptionsK8sClient(ctx)
		return getter.NewMergedExceptionsGetter(primary, getter.NewCRDExceptionsGetter(k8sClient)), nil
	}
	primary = downloadReleasedPolicy
	k8sClient := getExceptionsK8sClient(ctx)
	return getter.NewMergedExceptionsGetter(primary, getter.NewCRDExceptionsGetter(k8sClient)), nil

}

func getRBACHandler(tenantConfig cautils.ITenantConfig, k8s *k8sinterface.KubernetesApi, submit bool) *cautils.RBACObjects {
	if submit {
		return cautils.NewRBACObjects(rbacscanner.NewRbacScannerFromK8sAPI(k8s, tenantConfig.GetAccountID(), tenantConfig.GetContextName()))
	}
	return nil
}

func getReporter(ctx context.Context, tenantConfig cautils.ITenantConfig, reportID string, submit, fwScan bool, scanInfo cautils.ScanInfo) reporter.IReport {
	_, span := otel.Tracer("").Start(ctx, "getReporter")
	defer span.End()

	if submit {
		submitData := reporterv2.SubmitContextScan
		if scanInfo.GetScanningContext() != cautils.ContextCluster {
			submitData = reporterv2.SubmitContextRepository
		}
		return reporterv2.NewReportEventReceiver(tenantConfig, reportID, submitData, getter.GetKSCloudAPIConnector())
	}
	if tenantConfig.GetAccountID() == "" {
		// Add link only when scanning a cluster using a framework
		return reporterv2.NewReportMock("", "")
	}
	var message string

	if !fwScan && scanInfo.ScanType != cautils.ScanTypeWorkload {
		message = "Kubescape does not submit scan results when scanning controls"
	}

	return reporterv2.NewReportMock("", message)
}

func getResourceHandler(ctx context.Context, scanInfo *cautils.ScanInfo, tenantConfig cautils.ITenantConfig, k8s *k8sinterface.KubernetesApi, hostSensorHandler hostsensorutils.IHostSensor) resourcehandler.IResourceHandler {
	_, span := otel.Tracer("").Start(ctx, "getResourceHandler")
	defer span.End()

	if len(scanInfo.InputPatterns) > 0 || k8s == nil {
		// scanInfo.HostSensor.SetBool(false)
		return resourcehandler.NewFileResourceHandler()
	}

	// Only initialize cloud connector if not in air-gapped mode
	// This call initializes the global cloud API connector for later use
	if !isAirGappedMode(scanInfo) {
		_ = getter.GetKSCloudAPIConnector()
	}
	rbacObjects := getRBACHandler(tenantConfig, k8s, scanInfo.Submit.GetBool())
	return resourcehandler.NewK8sResourceHandler(ctx, k8s, hostSensorHandler, rbacObjects, tenantConfig.GetContextName())
}

// getHostSensorHandler yields a IHostSensor that knows how to collect a host's scanned resources.
//
// A noop sensor is returned whenever host scanning is disabled or an error prevented the scanner to properly deploy.
func getHostSensorHandler(ctx context.Context, scanInfo *cautils.ScanInfo, k8s *k8sinterface.KubernetesApi) hostsensorutils.IHostSensor {
	const wantsHostSensorControls = true // defaults to disabling the scanner if not explicitly enabled (TODO(fredbi): should be addressed by injecting ScanInfo defaults)
	hostSensorVal := scanInfo.HostSensorEnabled.Get()

	switch {
	case k8s == nil:
		// k8s is nil exactly when this scan never connected to a cluster (a
		// non-cluster scan, or getKubernetesApi() failing - which exits the
		// process via logger.Fatal before we'd get here). Re-checking
		// k8sinterface.IsConnectedToCluster() here as well used to read the
		// same global connection state a second time, at a later point than
		// when k8s was obtained, with no synchronization between the two
		// reads - a caller could observe k8s and IsConnectedToCluster()
		// disagree. k8s == nil is already a complete, single-read proxy for
		// "no cluster connection", so the second read added nothing but risk.
		return hostsensorutils.NewHostSensorHandlerMock()

	case hostSensorVal != nil && *hostSensorVal:
		hostSensorHandler, err := hostsensorutils.NewHostSensorHandler(k8s, scanInfo.HostSensorYamlPath)
		if err != nil {
			logger.L().Ctx(ctx).Warning("failed to create host scanner", helpers.Error(err))
			return hostsensorutils.NewHostSensorHandlerMock()
		}

		return hostSensorHandler

	case hostSensorVal == nil && wantsHostSensorControls:
		// Auto-detect: if node-agent CRDs are available, use them instead of deploying the host-sensor daemonset.
		hostSensorHandler, err := hostsensorutils.NewHostSensorHandler(k8s, "")
		if err != nil {
			logger.L().Ctx(ctx).Debug("node-agent not available, host sensor disabled", helpers.Error(err))
			scanInfo.HostSensorEnabled.SetBool(false)
			return hostsensorutils.NewHostSensorHandlerMock()
		}
		logger.L().Ctx(ctx).Info("node-agent detected, using CRD-based host sensor")
		scanInfo.HostSensorEnabled.SetBool(true)
		return hostSensorHandler

	default:
		return hostsensorutils.NewHostSensorHandlerMock()
	}
}

func policyIdentifierIdentities(pi []cautils.PolicyIdentifier) string {
	policiesIdentities := ""
	for i := range pi {
		policiesIdentities += pi[i].Identifier
		if i+1 < len(pi) {
			policiesIdentities += ","
		}
	}
	if policiesIdentities == "" {
		policiesIdentities = "all"
	}
	return policiesIdentities
}

// setSubmitBehavior - Setup the desired cluster behavior regarding submitting to the Kubescape Cloud BE
func setSubmitBehavior(scanInfo *cautils.ScanInfo, tenantConfig cautils.ITenantConfig) {

	/*
		If the caller explicitly opted out of submission (--submit=false, KS_SUBMIT=false,
		or the httphandler request body's submit:false) - Do not send report, and do not
		let the auto-detection below override that choice.

		If keep-local OR scan type which is not submittable - Do not send report

		If CloudReportURL not set - Do not send report

		If CloudReportURL is set
			If There is no account -
				Generate Account & Submit report

			If There is account -
				Invalid Account ID - Do not send report
				Valid Account - Submit report

	*/

	// respect an explicit opt-out - never auto-submit against the caller's wishes
	if explicit := scanInfo.Submit.Get(); explicit != nil && !*explicit {
		return
	}

	// do not submit control/workload scanning
	if !isScanTypeForSubmission(scanInfo.ScanType) || scanInfo.Local {
		scanInfo.Submit.SetBool(false)
		return
	}

	if tenantConfig.GetCloudReportURL() == "" {
		scanInfo.Submit.SetBool(false)
		return
	}

	// a new account will be created if a report URL is set and there is no account ID
	if tenantConfig.GetAccountID() == "" {
		scanInfo.Submit.SetBool(true)
		return
	}

	_, err := uuid.Parse(tenantConfig.GetAccountID())
	if err != nil {
		logger.L().Warning("account is not a valid UUID", helpers.Error(err))
	}

	// submit if account is valid
	scanInfo.Submit.SetBool(err == nil)
}

func isScanTypeForSubmission(scanType cautils.ScanTypes) bool {
	if scanType == cautils.ScanTypeControl || scanType == cautils.ScanTypeWorkload {
		return false
	}
	return true
}

// setPolicyGetter set the policy getter - local file/github release/Kubescape Cloud API
func getPolicyGetter(ctx context.Context, loadPoliciesFromFile []string, accountID string, frameworkScope bool, downloadReleasedPolicy *getter.DownloadReleasedPolicy, airGapped bool) (getter.IPolicyGetter, error) {
	if len(loadPoliciesFromFile) > 0 {
		return getter.NewLoadPolicy(loadPoliciesFromFile), nil
	}
	if airGapped {
		return getter.NewLoadPolicy(getDefaultFrameworksPaths()), nil
	}
	if accountID != "" && getter.GetKSCloudAPIConnector().GetCloudAPIURL() != "" && frameworkScope {
		if downloadReleasedPolicy != nil && downloadReleasedPolicy.IsVersionPinned() {
			logger.L().Ctx(ctx).Warning("--controls-version is ignored when an account ID is set; policies are downloaded from the Kubescape Cloud backend")
		}
		g := getter.GetKSCloudAPIConnector() // download policy from Kubescape Cloud backend
		return g, nil
	} else if accountID != "" && getter.GetKSCloudAPIConnector().GetCloudAPIURL() == "" && frameworkScope {
		logger.L().Ctx(ctx).Warning("Kubescape Cloud API URL is not set, loading policies from cache")
	}

	if downloadReleasedPolicy == nil {
		downloadReleasedPolicy = getter.NewDownloadReleasedPolicy()
	}
	return getDownloadReleasedPolicy(ctx, downloadReleasedPolicy)

}

// setConfigInputsGetter sets the config input getter with the following precedence:
//  1. Local file (--controls-config flag)
//  2. Kubescape Cloud API (if accountID configured)
//  3. ControlInput CRD in-cluster (if connected to cluster and CRD exists)
//  4. Defaults from regolibrary GitHub releases
//
// getConfigInputsGetter returns the control inputs getter and a bool reporting
// whether the inputs are served from the local cache fallback (GitHub download
// failed) rather than fetched fresh, so the caller can record a PolicyDegradation.
func getConfigInputsGetter(ctx context.Context, ControlsInputs string, accountID string, downloadReleasedPolicy *getter.DownloadReleasedPolicy, useCRD bool, airGapped bool) (getter.IControlsInputsGetter, bool, error) {
	if len(ControlsInputs) > 0 {
		return getter.NewLoadPolicy([]string{ControlsInputs}), false, nil
	}
	if airGapped {
		return getter.NewLoadPolicy([]string{getter.GetDefaultPath(cautils.LocalControlInputsFilename)}), false, nil
	}
	if accountID != "" {
		if downloadReleasedPolicy != nil && downloadReleasedPolicy.IsVersionPinned() {
			logger.L().Ctx(ctx).Warning("--controls-version is ignored for control config when an account ID is set; control config is downloaded from the Kubescape Cloud backend")
		}
		g := getter.GetKSCloudAPIAdapter() // download config from Kubescape Cloud backend
		return g, false, nil
	}

	// Try to read control inputs from the ControlInput CRD in-cluster (live cluster scans only)
	if useCRD {
		if crdInputs, err := getter.NewCRDControlInputs(); err == nil {
			if _, crdErr := crdInputs.GetControlsInputs(ctx, ""); crdErr == nil {
				logger.L().Ctx(ctx).Info("using ControlInput CRD for control configuration")
				return crdInputs, false, nil
			} else if isContextErr(crdErr) {
				return nil, false, crdErr
			}
			logger.L().Ctx(ctx).Debug("ControlInput CRD found but default resource not available, falling back")
		}
	}

	if downloadReleasedPolicy == nil {
		downloadReleasedPolicy = getter.NewDownloadReleasedPolicy()
	}
	if fallback, err := downloadReleasedPolicy.SetRegoObjectsWithFallback(); err != nil {
		// pinned version: hard error, surface it instead of silently degrading
		return nil, false, err
	} else if fallback { // if failed to pull config inputs, fallback to cache
		logger.L().Ctx(ctx).Warning("failed to get config inputs from github release, loading config inputs from cache")
		return getter.NewLoadPolicy([]string{getter.GetDefaultPath(cautils.LocalControlInputsFilename)}), true, nil
	}
	return downloadReleasedPolicy, false, nil
}

func getDownloadReleasedPolicy(ctx context.Context, downloadReleasedPolicy *getter.DownloadReleasedPolicy) (getter.IPolicyGetter, error) {
	if fallback, err := downloadReleasedPolicy.SetRegoObjectsWithFallback(); err != nil {
		// pinned version: hard error, do not silently serve cached policies
		return nil, err
	} else if fallback { // if failed to pull policy, fallback to cache
		logger.L().Ctx(ctx).Warning("failed to get policies from github release, loading policies from cache")
		return getter.NewLoadPolicy(getDefaultFrameworksPaths()), nil
	}
	return downloadReleasedPolicy, nil
}

func getDefaultFrameworksPaths() []string {
	fwPaths := []string{}
	for i := range getter.NativeFrameworks {
		fwPaths = append(fwPaths, getter.GetDefaultPath(getter.NativeFrameworks[i]+".json")) // GetDefaultPath expects a filename, not just the framework name
	}
	return fwPaths
}

// resolveDefaultScanAllPolicies expands a ScanAll framework list before ScanInfo.Init runs.
// Init's setUseFrom resolves a local cache path per identifier, so the ScanAll expansion that
// happens later - once the policy getter exists - would add frameworks that carry no cached
// path, leaving an offline scan with a downloader it cannot reach. --use-default makes the
// local store the policy source, so the expansion is answered from the default framework set
// instead of the getter, the same set getDefaultFrameworksPaths serves in air-gapped mode.
//
// Only framework scans are expanded. `scan control` with no arguments also sets ScanAll, but
// it is not a framework scan, and injecting KindFramework identifiers there would populate
// UseFrom and silently turn the scan air-gapped - dropping the downloader that control inputs,
// exceptions and attack tracks still fall back to.
func resolveDefaultScanAllPolicies(scanInfo *cautils.ScanInfo, policyIdentifiers []cautils.PolicyIdentifier) []cautils.PolicyIdentifier {
	if !scanInfo.ScanAll || !scanInfo.UseDefault || !scanInfo.FrameworkScan {
		return policyIdentifiers
	}
	return cautils.AppendPolicyIdentifiers(policyIdentifiers, getter.NativeFrameworks, apisv1.KindFramework)
}

func listFrameworksNames(policyGetter getter.IPolicyGetter) []string {
	fw, err := policyGetter.ListFrameworks()
	if err == nil {
		return fw
	} else {
		logger.L().Warning("failed to list frameworks", helpers.Error(err))
	}
	return getter.NativeFrameworks
}

func getAttackTracksGetter(ctx context.Context, attackTracks, accountID string, downloadReleasedPolicy *getter.DownloadReleasedPolicy, airGapped bool) (getter.IAttackTracksGetter, error) {
	if len(attackTracks) > 0 {
		return getter.NewLoadPolicy([]string{attackTracks}), nil
	}
	if airGapped {
		return getter.NewLoadPolicy([]string{getter.GetDefaultPath(cautils.LocalAttackTracksFilename)}), nil
	}
	if accountID != "" {
		if downloadReleasedPolicy != nil && downloadReleasedPolicy.IsVersionPinned() {
			logger.L().Ctx(ctx).Warning("--controls-version is ignored for attack tracks when an account ID is set; attack tracks are downloaded from the Kubescape Cloud backend")
		}
		g := getter.GetKSCloudAPIConnector() // download attack tracks from Kubescape Cloud backend
		return g, nil
	}
	if downloadReleasedPolicy == nil {
		downloadReleasedPolicy = getter.NewDownloadReleasedPolicy()
	}

	if fallback, err := downloadReleasedPolicy.SetRegoObjectsWithFallback(); err != nil {
		// pinned version: hard error, do not silently serve cached attack tracks
		return nil, err
	} else if fallback { // if failed to pull attack tracks, fallback to cache
		logger.L().Ctx(ctx).Warning("failed to get attack tracks from github release, loading attack tracks from cache")
		return getter.NewLoadPolicy([]string{getter.GetDefaultPath(cautils.LocalAttackTracksFilename)}), nil
	}
	return downloadReleasedPolicy, nil
}

// GetUIPrinter returns a printer that will be used to print to the program’s UI (terminal)
func GetUIPrinter(ctx context.Context, scanInfo *cautils.ScanInfo, clusterName string) printer.IPrinter {
	var p printer.IPrinter
	if helpers.ToLevel(logger.L().GetLevel()) >= helpers.WarningLevel {
		p = &printerv2.SilentPrinter{}
	} else {
		p = printerv2.NewPrettyPrinter(scanInfo.VerboseMode, scanInfo.FormatVersion, scanInfo.PrintAttackTree, cautils.ViewTypes(scanInfo.View), scanInfo.ScanType, scanInfo.InputPatterns, clusterName)

		// Since the UI of the program is a CLI (Stdout), it means that it should always print to Stdout
		if scanInfo.Format != "" && scanInfo.Output == "" {
			p.SetWriter(ctx, os.DevNull)
		} else {
			p.SetWriter(ctx, os.Stdout.Name())
		}
	}

	return p
}

// isContextErr reports whether err was caused by context cancellation or a deadline.
func isContextErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
