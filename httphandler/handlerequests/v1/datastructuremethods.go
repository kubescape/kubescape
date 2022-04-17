package v1

import (
	"strings"

	apisv1 "github.com/armosec/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/armosec/opa-utils/httpserver/meta/v1"

	"github.com/armosec/kubescape/v2/core/cautils"
	"github.com/armosec/kubescape/v2/core/cautils/getter"
	"github.com/armosec/opa-utils/reporthandling"
)

func ToScanInfo(scanRequest *utilsmetav1.PostScanRequest) *cautils.ScanInfo {
	scanInfo := defaultScanInfo()

	if scanRequest.TargetType != "" && len(scanRequest.TargetNames) > 0 {
		if strings.EqualFold(string(scanRequest.TargetType), string(reporthandling.KindFramework)) {
			scanRequest.TargetType = apisv1.KindFramework
			scanInfo.FrameworkScan = true
		} else if strings.EqualFold(string(scanRequest.TargetType), string(reporthandling.KindControl)) {
			scanRequest.TargetType = apisv1.KindControl
		} else {
			// unknown policy kind - set scan all
			scanInfo.FrameworkScan = true
			scanInfo.ScanAll = true
			scanRequest.TargetNames = []string{}
		}
		scanInfo.SetPolicyIdentifiers(scanRequest.TargetNames, scanRequest.TargetType)
		scanInfo.ScanAll = false
	} else {
		scanInfo.FrameworkScan = true
		scanInfo.ScanAll = true
	}

	if scanRequest.Account != "" {
		scanInfo.Account = scanRequest.Account
	}
	if len(scanRequest.ExcludedNamespaces) > 0 {
		scanInfo.ExcludedNamespaces = strings.Join(scanRequest.ExcludedNamespaces, ",")
	}
	if len(scanRequest.IncludeNamespaces) > 0 {
		scanInfo.IncludeNamespaces = strings.Join(scanRequest.IncludeNamespaces, ",")
	}

	if scanRequest.Format != "" {
		scanInfo.Format = scanRequest.Format
	}

	useCachedArtifacts := cautils.NewBoolPtr(scanRequest.UseCachedArtifacts)
	if useCachedArtifacts.Get() != nil && !*useCachedArtifacts.Get() {
		scanInfo.UseArtifactsFrom = getter.DefaultLocalStore // Load files from cache (this will prevent kubescape fom downloading the artifacts every time)
	}

	keepLocal := cautils.NewBoolPtr(scanRequest.KeepLocal)
	if keepLocal.Get() != nil {
		scanInfo.Local = *keepLocal.Get() // Load files from cache (this will prevent kubescape fom downloading the artifacts every time)
	}
	submit := cautils.NewBoolPtr(scanRequest.Submit)
	if submit.Get() != nil {
		scanInfo.Submit = *submit.Get()
	}
	scanInfo.HostSensorEnabled = cautils.NewBoolPtr(scanRequest.HostScanner)

	return scanInfo
}
