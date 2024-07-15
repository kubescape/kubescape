package core

import (
	"context"
	"fmt"
	"os"

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
	"go.opentelemetry.io/otel"

	"github.com/google/uuid"

	"github.com/kubescape/rbac-utils/rbacscanner"
)

// getKubernetesApi
func getKubernetesApi() *k8sinterface.KubernetesApi {
	if !k8sinterface.IsConnectedToCluster() {
		return nil
	}
	return k8sinterface.NewKubernetesApi()
}

func getExceptionsGetter(ctx context.Context, useExceptions string, accountID string, downloadReleasedPolicy *getter.DownloadReleasedPolicy) getter.IExceptionsGetter {
	if useExceptions != "" {
		// load exceptions from file
		return getter.NewLoadPolicy([]string{useExceptions})
	}
	if accountID != "" {
		// download exceptions from Kubescape Cloud backend
		return getter.GetKSCloudAPIConnector()
	}
	// download exceptions from GitHub
	if downloadReleasedPolicy == nil {
		downloadReleasedPolicy = getter.NewDownloadReleasedPolicy()
	}
	if err := downloadReleasedPolicy.SetRegoObjects(); err != nil { // if failed to pull attack tracks, fallback to cache
		logger.L().Ctx(ctx).Warning("failed to get exceptions from github release, loading attack tracks from cache", helpers.Error(err))
		return getter.NewLoadPolicy([]string{getter.GetDefaultPath(cautils.LocalExceptionsFilename)})
	}
	return downloadReleasedPolicy

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
	ctx, span := otel.Tracer("").Start(ctx, "getResourceHandler")
	defer span.End()

	if len(scanInfo.InputPatterns) > 0 || k8s == nil {
		// scanInfo.HostSensor.SetBool(false)
		return resourcehandler.NewFileResourceHandler()
	}

	getter.GetKSCloudAPIConnector()
	rbacObjects := getRBACHandler(tenantConfig, k8s, scanInfo.Submit)
	return resourcehandler.NewK8sResourceHandler(k8s, hostSensorHandler, rbacObjects, tenantConfig.GetContextName())
}

// getHostSensorHandler yields a IHostSensor that knows how to collect a host's scanned resources.
//
// A noop sensor is returned whenever host scanning is disabled or an error prevented the scanner to properly deploy.
func getHostSensorHandler(ctx context.Context, scanInfo *cautils.ScanInfo, k8s *k8sinterface.KubernetesApi) hostsensorutils.IHostSensor {
	const wantsHostSensorControls = true // defaults to disabling the scanner if not explictly enabled (TODO(fredbi): should be addressed by injecting ScanInfo defaults)
	hostSensorVal := scanInfo.HostSensorEnabled.Get()

	switch {
	case !k8sinterface.IsConnectedToCluster() || k8s == nil: // TODO(fred): fix race condition on global KSConfig there
		return hostsensorutils.NewHostSensorHandlerMock()

	case hostSensorVal != nil && *hostSensorVal:
		hostSensorHandler, err := hostsensorutils.NewHostSensorHandler(k8s, scanInfo.HostSensorYamlPath)
		if err != nil {
			logger.L().Ctx(ctx).Warning(fmt.Sprintf("failed to create host scanner: %s", err.Error()))

			return hostsensorutils.NewHostSensorHandlerMock()
		}

		return hostSensorHandler

	case hostSensorVal == nil && wantsHostSensorControls:
		// TODO: we need to determine which controls need the host scanner
		scanInfo.HostSensorEnabled.SetBool(false)

		fallthrough

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
		If keep-local OR scan type which is not submittable - Do not send report

		If CloudReportURL not set - Do not send report

		If CloudReportURL is set
			If There is no account -
				Generate Account & Submit report

			If There is account -
				Invalid Account ID - Do not send report
				Valid Account - Submit report

	*/

	// do not submit control/workload scanning
	if !isScanTypeForSubmission(scanInfo.ScanType) || scanInfo.Local {
		scanInfo.Submit = false
		return
	}

	if tenantConfig.GetCloudReportURL() == "" {
		scanInfo.Submit = false
		return
	}

	// a new account will be created if a report URL is set and there is no account ID
	if tenantConfig.GetAccountID() == "" {
		scanInfo.Submit = true
		return
	}

	_, err := uuid.Parse(tenantConfig.GetAccountID())
	if err != nil {
		logger.L().Warning("account is not a valid UUID", helpers.Error(err))
	}

	// submit if account is valid
	scanInfo.Submit = err == nil
}

func isScanTypeForSubmission(scanType cautils.ScanTypes) bool {
	if scanType == cautils.ScanTypeControl || scanType == cautils.ScanTypeWorkload {
		return false
	}
	return true
}

// setPolicyGetter set the policy getter - local file/github release/Kubescape Cloud API
func getPolicyGetter(ctx context.Context, loadPoliciesFromFile []string, accountID string, frameworkScope bool, downloadReleasedPolicy *getter.DownloadReleasedPolicy) getter.IPolicyGetter {
	if len(loadPoliciesFromFile) > 0 {
		return getter.NewLoadPolicy(loadPoliciesFromFile)
	}
	if accountID != "" && getter.GetKSCloudAPIConnector().GetCloudAPIURL() != "" && frameworkScope {
		g := getter.GetKSCloudAPIConnector() // download policy from Kubescape Cloud backend
		return g
	} else if accountID != "" && getter.GetKSCloudAPIConnector().GetCloudAPIURL() == "" && frameworkScope {
		logger.L().Ctx(ctx).Warning("Kubescape Cloud API URL is not set, loading policies from cache")
	}

	if downloadReleasedPolicy == nil {
		downloadReleasedPolicy = getter.NewDownloadReleasedPolicy()
	}
	return getDownloadReleasedPolicy(ctx, downloadReleasedPolicy)

}

// setConfigInputsGetter sets the config input getter - local file/github release/Kubescape Cloud API
func getConfigInputsGetter(ctx context.Context, ControlsInputs string, accountID string, downloadReleasedPolicy *getter.DownloadReleasedPolicy) getter.IControlsInputsGetter {
	if len(ControlsInputs) > 0 {
		return getter.NewLoadPolicy([]string{ControlsInputs})
	}
	if accountID != "" {
		g := getter.GetKSCloudAPIConnector() // download config from Kubescape Cloud backend
		return g
	}
	if downloadReleasedPolicy == nil {
		downloadReleasedPolicy = getter.NewDownloadReleasedPolicy()
	}
	if err := downloadReleasedPolicy.SetRegoObjects(); err != nil { // if failed to pull config inputs, fallback to BE
		logger.L().Ctx(ctx).Warning("failed to get config inputs from github release, this may affect the scanning results", helpers.Error(err))
	}
	return downloadReleasedPolicy
}

func getDownloadReleasedPolicy(ctx context.Context, downloadReleasedPolicy *getter.DownloadReleasedPolicy) getter.IPolicyGetter {
	if err := downloadReleasedPolicy.SetRegoObjects(); err != nil { // if failed to pull policy, fallback to cache
		logger.L().Ctx(ctx).Warning("failed to get policies from github release, loading policies from cache", helpers.Error(err))
		return getter.NewLoadPolicy(getDefaultFrameworksPaths())
	} else {
		return downloadReleasedPolicy
	}
}

func getDefaultFrameworksPaths() []string {
	fwPaths := []string{}
	for i := range getter.NativeFrameworks {
		fwPaths = append(fwPaths, getter.GetDefaultPath(getter.NativeFrameworks[i]+".json")) // GetDefaultPath expects a filename, not just the framework name
	}
	return fwPaths
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

func getAttackTracksGetter(ctx context.Context, attackTracks, accountID string, downloadReleasedPolicy *getter.DownloadReleasedPolicy) getter.IAttackTracksGetter {
	if len(attackTracks) > 0 {
		return getter.NewLoadPolicy([]string{attackTracks})
	}
	if accountID != "" {
		g := getter.GetKSCloudAPIConnector() // download attack tracks from Kubescape Cloud backend
		return g
	}
	if downloadReleasedPolicy == nil {
		downloadReleasedPolicy = getter.NewDownloadReleasedPolicy()
	}

	if err := downloadReleasedPolicy.SetRegoObjects(); err != nil { // if failed to pull attack tracks, fallback to cache
		logger.L().Ctx(ctx).Warning("failed to get attack tracks from github release, loading attack tracks from cache", helpers.Error(err))
		return getter.NewLoadPolicy([]string{getter.GetDefaultPath(cautils.LocalAttackTracksFilename)})
	}
	return downloadReleasedPolicy
}

// getUIPrinter returns a printer that will be used to print to the program’s UI (terminal)
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
