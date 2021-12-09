package clihandler

import (
	"fmt"
	"os"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/getter"
	"github.com/armosec/kubescape/resourcehandler"
	"github.com/armosec/kubescape/resultshandling/reporter"
	"github.com/armosec/opa-utils/reporthandling"
	"github.com/golang/glog"
)

func getReporter(scanInfo *cautils.ScanInfo, tenantConfig cautils.ITenantConfig) reporter.IReport {
	setSubmitBehavior(scanInfo, tenantConfig)

	if !scanInfo.Submit {
		return reporter.NewReportMock()
	}
	if !scanInfo.FrameworkScan {
		return reporter.NewReportMock()
	}

	return reporter.NewReportEventReceiver(tenantConfig.GetConfigObj())
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
func setPolicyGetter(scanInfo *cautils.ScanInfo, customerGUID string) {
	if len(scanInfo.UseFrom) > 0 {
		scanInfo.PolicyGetter = getter.NewLoadPolicy(scanInfo.UseFrom)
	} else {
		if customerGUID == "" || !scanInfo.FrameworkScan {
			setDownloadReleasedPolicy(scanInfo)
		} else {
			setGetArmoAPIConnector(scanInfo, customerGUID)
		}
	}
}

func setDownloadReleasedPolicy(scanInfo *cautils.ScanInfo) {
	g := getter.NewDownloadReleasedPolicy()    // download policy from github release
	if err := g.SetRegoObjects(); err != nil { // if failed to pull policy, fallback to cache
		cautils.WarningDisplay(os.Stdout, "Warning: failed to get policies from github release, loading policies from cache\n")
		scanInfo.PolicyGetter = getter.NewLoadPolicy(getDefaultFrameworksPaths())
	} else {
		scanInfo.PolicyGetter = g
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
