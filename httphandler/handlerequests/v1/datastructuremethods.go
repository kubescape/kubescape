package v1

import (
	"strings"

	"github.com/armosec/kubescape/core/cautils"
	"github.com/armosec/kubescape/core/cautils/getter"
	"github.com/armosec/opa-utils/reporthandling"
)

func (scanRequest *PostScanRequest) ToScanInfo() *cautils.ScanInfo {
	scanInfo := defaultScanInfo()

	if scanRequest.TargetType != nil && len(scanRequest.TargetNames) > 0 {
		if *scanRequest.TargetType == reporthandling.KindFramework {
			scanInfo.FrameworkScan = true
		}
		scanInfo.SetPolicyIdentifiers(scanRequest.TargetNames, *scanRequest.TargetType)
		scanInfo.ScanAll = false
	} else {
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

	if scanRequest.Format == "" {
		scanInfo.Format = scanRequest.Format // TODO - handle default
	}

	if scanRequest.UseCachedArtifacts.Get() != nil && !*scanRequest.UseCachedArtifacts.Get() {
		scanInfo.UseArtifactsFrom = getter.DefaultLocalStore // Load files from cache (this will prevent kubescape fom downloading the artifacts every time)
	}

	if scanRequest.KeepLocal.Get() != nil {
		scanInfo.Local = *scanRequest.KeepLocal.Get() // Load files from cache (this will prevent kubescape fom downloading the artifacts every time)
	}
	if scanRequest.Submit.Get() != nil {
		scanInfo.Submit = *scanRequest.Submit.Get()
	}
	scanInfo.HostSensorEnabled = scanRequest.HostScanner

	return scanInfo
}
