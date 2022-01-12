package clihandler

import (
	"fmt"
	"os"

	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/getter"
	"github.com/armosec/kubescape/hostsensorutils"
	"github.com/armosec/kubescape/resourcehandler"
	"github.com/armosec/kubescape/resultshandling/reporter"
	reporterv1 "github.com/armosec/kubescape/resultshandling/reporter/v1"

	reporterv2 "github.com/armosec/kubescape/resultshandling/reporter/v2"
	"github.com/armosec/opa-utils/reporthandling"
	"github.com/armosec/rbac-utils/rbacscanner"
)

// getKubernetesApi
func getKubernetesApi() *k8sinterface.KubernetesApi {
	if !k8sinterface.IsConnectedToCluster() {
		return nil
	}
	return k8sinterface.NewKubernetesApi()
}
func getTenantConfig(Account, clusterName string, k8s *k8sinterface.KubernetesApi) cautils.ITenantConfig {
	if !k8sinterface.IsConnectedToCluster() || k8s == nil {
		return cautils.NewLocalConfig(getter.GetArmoAPIConnector(), Account, clusterName)
	}
	return cautils.NewClusterConfig(k8s, getter.GetArmoAPIConnector(), Account, clusterName)
}

func getExceptionsGetter(useExceptions string) getter.IExceptionsGetter {
	if useExceptions != "" {
		// load exceptions from file
		return getter.NewLoadPolicy([]string{useExceptions})
	} else {
		return getter.GetArmoAPIConnector()
	}
}

func getRBACHandler(tenantConfig cautils.ITenantConfig, k8s *k8sinterface.KubernetesApi, submit bool) *cautils.RBACObjects {
	if submit {
		return cautils.NewRBACObjects(rbacscanner.NewRbacScannerFromK8sAPI(k8s, tenantConfig.GetCustomerGUID(), tenantConfig.GetClusterName()))
	}
	return nil
}

func getReporter(tenantConfig cautils.ITenantConfig, submit bool) reporter.IReport {
	if submit {
		// return reporterv1.NewReportEventReceiver(tenantConfig.GetConfigObj())
		return reporterv2.NewReportEventReceiver(tenantConfig.GetConfigObj())
	}
	return reporterv1.NewReportMock()
}

func getResourceHandler(scanInfo *cautils.ScanInfo, tenantConfig cautils.ITenantConfig, k8s *k8sinterface.KubernetesApi, hostSensorHandler hostsensorutils.IHostSensor) resourcehandler.IResourceHandler {
	if len(scanInfo.InputPatterns) > 0 || k8s == nil {
		return resourcehandler.NewFileResourceHandler(scanInfo.InputPatterns)
	}
	rbacObjects := getRBACHandler(tenantConfig, k8s, scanInfo.Submit)
	return resourcehandler.NewK8sResourceHandler(k8s, getFieldSelector(scanInfo), hostSensorHandler, rbacObjects)
}

func getHostSensorHandler(scanInfo *cautils.ScanInfo, k8s *k8sinterface.KubernetesApi) hostsensorutils.IHostSensor {
	if !k8sinterface.IsConnectedToCluster() || k8s == nil {
		return &hostsensorutils.HostSensorHandlerMock{}
	}

	hasHostSensorControls := true
	// we need to determined which controls needs host sensor
	if scanInfo.HostSensor.Get() == nil && hasHostSensorControls {
		scanInfo.HostSensor.SetBool(askUserForHostSensor())
		cautils.WarningDisplay(os.Stderr, "Warning: Kubernetes cluster nodes scanning is disabled. This is required to collect valuable data for certain controls. You can enable it using  the --enable-host-scan flag\n")
	}
	if hostSensorVal := scanInfo.HostSensor.Get(); hostSensorVal != nil && *hostSensorVal {
		hostSensorHandler, err := hostsensorutils.NewHostSensorHandler(k8s)
		if err != nil {
			cautils.WarningDisplay(os.Stderr, fmt.Sprintf("Warning: failed to create host sensor: %v\n", err.Error()))
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

func policyIdentifierNames(pi []reporthandling.PolicyIdentifier) string {
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

// setSubmitBehavior - Setup the desired cluster behavior regarding submittion to the Armo BE
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

	if tenantConfig.IsConfigFound() { // config found in cache (submitted)
		if !scanInfo.Local {
			// Submit report
			scanInfo.Submit = true
		}
	} else { // config not found in cache (not submitted)
		if scanInfo.Submit {
			// submit - Create tenant & Submit report
			if err := tenantConfig.SetTenant(); err != nil {
				fmt.Println(err)
			}
		}
	}
}

// setPolicyGetter set the policy getter - local file/github release/ArmoAPI
func getPolicyGetter(loadPoliciesFromFile []string, accountID string, frameworkScope bool, downloadReleasedPolicy *getter.DownloadReleasedPolicy) getter.IPolicyGetter {
	if len(loadPoliciesFromFile) > 0 {
		return getter.NewLoadPolicy(loadPoliciesFromFile)
	}
	if accountID != "" && frameworkScope {
		g := getter.GetArmoAPIConnector() // download policy from ARMO backend
		g.SetCustomerGUID(accountID)
		return g
	}
	if downloadReleasedPolicy == nil {
		downloadReleasedPolicy = getter.NewDownloadReleasedPolicy()
	}
	return getDownloadReleasedPolicy(downloadReleasedPolicy)

}

// func setGetArmoAPIConnector(scanInfo *cautils.ScanInfo, customerGUID string) {
// 	g := getter.GetArmoAPIConnector() // download policy from ARMO backend
// 	g.SetCustomerGUID(customerGUID)
// 	scanInfo.PolicyGetter = g
// 	if scanInfo.ScanAll {
// 		frameworks, err := g.ListCustomFrameworks(customerGUID)
// 		if err != nil {
// 			glog.Error("failed to get custom frameworks") // handle error
// 			return
// 		}
// 		scanInfo.SetPolicyIdentifiers(frameworks, reporthandling.KindFramework)
// 	}
// }

// setConfigInputsGetter sets the config input getter - local file/github release/ArmoAPI
func getConfigInputsGetter(ControlsInputs string, accountID string, downloadReleasedPolicy *getter.DownloadReleasedPolicy) getter.IControlsInputsGetter {
	if len(ControlsInputs) > 0 {
		return getter.NewLoadPolicy([]string{ControlsInputs})
	}
	if accountID != "" {
		g := getter.GetArmoAPIConnector() // download config from ARMO backend
		g.SetCustomerGUID(accountID)
		return g
	}
	if downloadReleasedPolicy == nil {
		downloadReleasedPolicy = getter.NewDownloadReleasedPolicy()
	}
	if err := downloadReleasedPolicy.SetRegoObjects(); err != nil { // if failed to pull config inputs, fallback to BE
		cautils.WarningDisplay(os.Stderr, "Warning: failed to get config inputs from github release, this may affect the scanning results\n")
	}
	return downloadReleasedPolicy
}

func getDownloadReleasedPolicy(downloadReleasedPolicy *getter.DownloadReleasedPolicy) getter.IPolicyGetter {
	if err := downloadReleasedPolicy.SetRegoObjects(); err != nil { // if failed to pull policy, fallback to cache
		cautils.WarningDisplay(os.Stderr, "Warning: failed to get policies from github release, loading policies from cache\n")
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
	if err != nil {
		fw = getDefaultFrameworksPaths()
	}
	return fw
}
