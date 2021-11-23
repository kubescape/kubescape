package clihandler

import (
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/resourcehandler"
	"github.com/armosec/kubescape/resultshandling/reporter"
	"github.com/armosec/opa-utils/reporthandling"
)

func getReporter(scanInfo *cautils.ScanInfo) reporter.IReport {
	if !scanInfo.Submit {
		return reporter.NewReportMock()
	}
	if !scanInfo.FrameworkScan {
		return reporter.NewReportMock()
	}

	return reporter.NewReportEventReceiver("", "")
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
