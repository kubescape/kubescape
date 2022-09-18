package core

import (
	"fmt"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/cautils/getter"
	"github.com/kubescape/kubescape/v2/core/pkg/hostsensorutils"
	"github.com/kubescape/kubescape/v2/core/pkg/resourcehandler"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/reporter"
	reporterv2 "github.com/kubescape/kubescape/v2/core/pkg/resultshandling/reporter/v2"

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
func getTenantConfig(credentials *cautils.Credentials, clusterName string, customClusterName string, k8s *k8sinterface.KubernetesApi) cautils.ITenantConfig {
	if !k8sinterface.IsConnectedToCluster() || k8s == nil {
		return cautils.NewLocalConfig(getter.GetKSCloudAPIConnector(), credentials, clusterName, customClusterName)
	}
	return cautils.NewClusterConfig(k8s, getter.GetKSCloudAPIConnector(), credentials, clusterName, customClusterName)
}

func getExceptionsGetter(useExceptions string) getter.IExceptionsGetter {
	if useExceptions != "" {
		// load exceptions from file
		return getter.NewLoadPolicy([]string{useExceptions})
	} else {
		return getter.GetKSCloudAPIConnector()
	}
}

func getRBACHandler(tenantConfig cautils.ITenantConfig, k8s *k8sinterface.KubernetesApi, submit bool) *cautils.RBACObjects {
	if submit {
		return cautils.NewRBACObjects(rbacscanner.NewRbacScannerFromK8sAPI(k8s, tenantConfig.GetAccountID(), tenantConfig.GetContextName()))
	}
	return nil
}

func getReporter(tenantConfig cautils.ITenantConfig, reportID string, submit, fwScan bool, scanningContext cautils.ScanningContext) reporter.IReport {
	if submit {
		submitData := reporterv2.SubmitContextScan
		if scanningContext != cautils.ContextCluster {
			submitData = reporterv2.SubmitContextRepository
		}
		return reporterv2.NewReportEventReceiver(tenantConfig.GetConfigObj(), reportID, submitData)
	}
	if tenantConfig.GetAccountID() == "" {
		// Add link only when scanning a cluster using a framework
		return reporterv2.NewReportMock(reporterv2.NO_SUBMIT_QUERY, "run kubescape with the '--submit' flag")
	}
	var message string
	if !fwScan {
		message = "Kubescape does not submit scan results when scanning controls"
	}

	return reporterv2.NewReportMock("", message)
}

func getResourceHandler(scanInfo *cautils.ScanInfo, tenantConfig cautils.ITenantConfig, k8s *k8sinterface.KubernetesApi, hostSensorHandler hostsensorutils.IHostSensor, registryAdaptors *resourcehandler.RegistryAdaptors) resourcehandler.IResourceHandler {
	if len(scanInfo.InputPatterns) > 0 || k8s == nil {
		// scanInfo.HostSensor.SetBool(false)
		return resourcehandler.NewFileResourceHandler(scanInfo.InputPatterns, registryAdaptors)
	}
	getter.GetKSCloudAPIConnector()
	rbacObjects := getRBACHandler(tenantConfig, k8s, scanInfo.Submit)
	return resourcehandler.NewK8sResourceHandler(k8s, getFieldSelector(scanInfo), hostSensorHandler, rbacObjects, registryAdaptors)
}

func getHostSensorHandler(scanInfo *cautils.ScanInfo, k8s *k8sinterface.KubernetesApi) hostsensorutils.IHostSensor {
	if !k8sinterface.IsConnectedToCluster() || k8s == nil {
		return &hostsensorutils.HostSensorHandlerMock{}
	}

	hasHostSensorControls := true
	// we need to determined which controls needs host scanner
	if scanInfo.HostSensorEnabled.Get() == nil && hasHostSensorControls {
		scanInfo.HostSensorEnabled.SetBool(false) // default - do not run host scanner
		logger.L().Warning("Kubernetes cluster nodes scanning is disabled. This is required to collect valuable data for certain controls. You can enable it using  the --enable-host-scan flag")
	}
	if hostSensorVal := scanInfo.HostSensorEnabled.Get(); hostSensorVal != nil && *hostSensorVal {
		hostSensorHandler, err := hostsensorutils.NewHostSensorHandler(k8s, scanInfo.HostSensorYamlPath)
		if err != nil {
			logger.L().Warning(fmt.Sprintf("failed to create host scanner: %s", err.Error()))
			return &hostsensorutils.HostSensorHandlerMock{}
		}
		return hostSensorHandler
	}
	return &hostsensorutils.HostSensorHandlerMock{}
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

func policyIdentifierNames(pi []cautils.PolicyIdentifier) string {
	policiesNames := ""
	for i := range pi {
		policiesNames += pi[i].Name
		if i+1 < len(pi) {
			policiesNames += ","
		}
	}
	if policiesNames == "" {
		policiesNames = "all"
	}
	return policiesNames
}

// setSubmitBehavior - Setup the desired cluster behavior regarding submitting to the Kubescape Cloud BE
func setSubmitBehavior(scanInfo *cautils.ScanInfo, tenantConfig cautils.ITenantConfig) {

	/*
		If "First run (local config not found)" -
			Default/keep-local - Do not send report
			Submit - Create tenant & Submit report

		If "Submitted" -
			keep-local - Do not send report
			Default/Submit - Submit report

	*/

	// do not submit control scanning
	if !scanInfo.FrameworkScan {
		scanInfo.Submit = false
		return
	}

	scanningContext := scanInfo.GetScanningContext()
	if scanningContext == cautils.ContextFile || scanningContext == cautils.ContextDir {
		scanInfo.Submit = false
		return
	}

	if tenantConfig.IsConfigFound() { // config found in cache (submitted)
		if !scanInfo.Local {
			if tenantConfig.GetAccountID() != "" {
				if _, err := uuid.Parse(tenantConfig.GetAccountID()); err != nil {
					scanInfo.Submit = false
					return
				}
			}
			// Submit report
			scanInfo.Submit = true
		}
	}

}

// setPolicyGetter set the policy getter - local file/github release/Kubescape Cloud API
func getPolicyGetter(loadPoliciesFromFile []string, tennatEmail string, frameworkScope bool, downloadReleasedPolicy *getter.DownloadReleasedPolicy) getter.IPolicyGetter {
	if len(loadPoliciesFromFile) > 0 {
		return getter.NewLoadPolicy(loadPoliciesFromFile)
	}
	if tennatEmail != "" && frameworkScope {
		g := getter.GetKSCloudAPIConnector() // download policy from Kubescape Cloud backend
		return g
	}
	if downloadReleasedPolicy == nil {
		downloadReleasedPolicy = getter.NewDownloadReleasedPolicy()
	}
	return getDownloadReleasedPolicy(downloadReleasedPolicy)

}

// setConfigInputsGetter sets the config input getter - local file/github release/Kubescape Cloud API
func getConfigInputsGetter(ControlsInputs string, accountID string, downloadReleasedPolicy *getter.DownloadReleasedPolicy) getter.IControlsInputsGetter {
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
		logger.L().Warning("failed to get config inputs from github release, this may affect the scanning results", helpers.Error(err))
	}
	return downloadReleasedPolicy
}

func getDownloadReleasedPolicy(downloadReleasedPolicy *getter.DownloadReleasedPolicy) getter.IPolicyGetter {
	if err := downloadReleasedPolicy.SetRegoObjects(); err != nil { // if failed to pull policy, fallback to cache
		logger.L().Warning("failed to get policies from github release, loading policies from cache", helpers.Error(err))
		return getter.NewLoadPolicy(getDefaultFrameworksPaths())
	} else {
		return downloadReleasedPolicy
	}
}

func getDefaultFrameworksPaths() []string {
	fwPaths := []string{}
	for i := range getter.NativeFrameworks {
		fwPaths = append(fwPaths, getter.GetDefaultPath(getter.NativeFrameworks[i]))
	}
	return fwPaths
}

func listFrameworksNames(policyGetter getter.IPolicyGetter) []string {
	fw, err := policyGetter.ListFrameworks()
	if err == nil {
		return fw
	}
	return getter.NativeFrameworks
}

func getAttackTracksGetter(accountID string, downloadReleasedPolicy *getter.DownloadReleasedPolicy) getter.IAttackTracksGetter {
	if accountID != "" {
		g := getter.GetKSCloudAPIConnector() // download attack tracks from Kubescape Cloud backend
		return g
	}
	if downloadReleasedPolicy == nil {
		downloadReleasedPolicy = getter.NewDownloadReleasedPolicy()
	}
	if err := downloadReleasedPolicy.SetRegoObjects(); err != nil {
		logger.L().Warning("failed to get attack tracks from github release, this may affect the scanning results", helpers.Error(err))
	}
	return downloadReleasedPolicy
}
