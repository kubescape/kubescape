package clihandler

import (
	"fmt"

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

func setPolicyGetter(scanInfo *cautils.ScanInfo, customerGUID string) {
	if len(scanInfo.UseFrom) > 0 {
		//load from file
		scanInfo.PolicyGetter = getter.NewLoadPolicy(scanInfo.UseFrom)
	} else {
		if customerGUID == "" || !scanInfo.FrameworkScan {
			scanInfo.PolicyGetter = getter.NewDownloadReleasedPolicy() // download policy from github release
		} else {
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
	}
}
