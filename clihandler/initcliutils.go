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
	"github.com/armosec/opa-utils/reporthandling"
	"github.com/armosec/rbac-utils/rbacscanner"
	"github.com/golang/glog"
)

func getKubernetesApi(scanInfo *cautils.ScanInfo) *k8sinterface.KubernetesApi {
	if scanInfo.GetScanningEnvironment() == cautils.ScanLocalFiles {
		return nil
	}
	return k8sinterface.NewKubernetesApi()
}
func getTenantConfig(scanInfo *cautils.ScanInfo, k8s *k8sinterface.KubernetesApi) cautils.ITenantConfig {
	if scanInfo.GetScanningEnvironment() == cautils.ScanLocalFiles {
		return cautils.NewLocalConfig(getter.GetArmoAPIConnector(), scanInfo.Account)
	}
	return cautils.NewClusterConfig(k8s, getter.GetArmoAPIConnector(), scanInfo.Account)
}

func getRBACHandler(tenantConfig cautils.ITenantConfig, k8s *k8sinterface.KubernetesApi, submit bool) *cautils.RBACObjects {
	if submit {
		return cautils.NewRBACObjects(rbacscanner.NewRbacScannerFromK8sAPI(k8s, tenantConfig.GetCustomerGUID(), tenantConfig.GetClusterName()))
	}
	return nil
}

func getReporter(tenantConfig cautils.ITenantConfig, submit bool) reporter.IReport {
	if submit {
		return reporter.NewReportEventReceiver(tenantConfig.GetConfigObj())
	}
	return reporter.NewReportMock()
}
func getResourceHandler(scanInfo *cautils.ScanInfo, tenantConfig cautils.ITenantConfig, k8s *k8sinterface.KubernetesApi, hostSensorHandler hostsensorutils.IHostSensor) resourcehandler.IResourceHandler {
	if scanInfo.GetScanningEnvironment() == cautils.ScanLocalFiles {
		return resourcehandler.NewFileResourceHandler(scanInfo.InputPatterns)
	}
	rbacObjects := getRBACHandler(tenantConfig, k8s, scanInfo.Submit)
	return resourcehandler.NewK8sResourceHandler(k8s, getFieldSelector(scanInfo), hostSensorHandler, rbacObjects)
}

func getHostSensorHandler(scanInfo *cautils.ScanInfo, k8s *k8sinterface.KubernetesApi) hostsensorutils.IHostSensor {
	if scanInfo.GetScanningEnvironment() == cautils.ScanLocalFiles {
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

	// do not submit yaml/url scanning
	if scanInfo.GetScanningEnvironment() == cautils.ScanLocalFiles {
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
func setPolicyGetter(scanInfo *cautils.ScanInfo, customerGUID string, downloadReleasedPolicy *getter.DownloadReleasedPolicy) {
	if len(scanInfo.UseFrom) > 0 {
		scanInfo.PolicyGetter = getter.NewLoadPolicy(scanInfo.UseFrom)
	} else {
		if customerGUID == "" || !scanInfo.FrameworkScan {
			setDownloadReleasedPolicy(scanInfo, downloadReleasedPolicy)
		} else {
			setGetArmoAPIConnector(scanInfo, customerGUID)
		}
	}
}

// setConfigInputsGetter sets the config input getter - local file/github release/ArmoAPI
func setConfigInputsGetter(scanInfo *cautils.ScanInfo, customerGUID string, downloadReleasedPolicy *getter.DownloadReleasedPolicy) {
	if len(scanInfo.ControlsInputs) > 0 {
		scanInfo.Getters.ControlsInputsGetter = getter.NewLoadPolicy([]string{scanInfo.ControlsInputs})
	} else {
		if customerGUID != "" {
			scanInfo.Getters.ControlsInputsGetter = getter.GetArmoAPIConnector()
		} else {
			if err := downloadReleasedPolicy.SetRegoObjects(); err != nil { // if failed to pull config inputs, fallback to BE
				cautils.WarningDisplay(os.Stderr, "Warning: failed to get config inputs from github release, this may affect the scanning results\n")
			}
			scanInfo.Getters.ControlsInputsGetter = downloadReleasedPolicy
		}
	}
}

func setDownloadReleasedPolicy(scanInfo *cautils.ScanInfo, downloadReleasedPolicy *getter.DownloadReleasedPolicy) {
	if err := downloadReleasedPolicy.SetRegoObjects(); err != nil { // if failed to pull policy, fallback to cache
		cautils.WarningDisplay(os.Stderr, "Warning: failed to get policies from github release, loading policies from cache\n")
		scanInfo.PolicyGetter = getter.NewLoadPolicy(getDefaultFrameworksPaths())
	} else {
		scanInfo.PolicyGetter = downloadReleasedPolicy
	}
}
func setGetArmoAPIConnector(scanInfo *cautils.ScanInfo, customerGUID string) {
	g := getter.GetArmoAPIConnector() // download policy from ARMO backend
	g.SetCustomerGUID(customerGUID)
	scanInfo.PolicyGetter = g
	if scanInfo.ScanAll {
		frameworks, err := g.ListCustomFrameworks(customerGUID)
		if err != nil {
			glog.Error("failed to get custom frameworks") // handle error
			return
		}
		scanInfo.SetPolicyIdentifiers(frameworks, reporthandling.KindFramework)
	}
}
func getDefaultFrameworksPaths() []string {
	fwPaths := []string{}
	for i := range getter.NativeFrameworks {
		fwPaths = append(fwPaths, getter.GetDefaultPath(getter.NativeFrameworks[i]))
	}
	return fwPaths
}
