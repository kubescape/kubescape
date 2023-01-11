package v1

import (
	"strings"

	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	"k8s.io/utils/strings/slices"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/cautils/getter"
)

func ToScanInfo(scanRequest *utilsmetav1.PostScanRequest) *cautils.ScanInfo {
	scanInfo := defaultScanInfo()

	setTargetInScanInfo(scanRequest, scanInfo)

	if scanRequest.Account != "" {
		scanInfo.Credentials.Account = scanRequest.Account
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

	// UseCachedArtifacts
	if scanRequest.UseCachedArtifacts != nil {
		if useCachedArtifacts := cautils.NewBoolPtr(scanRequest.UseCachedArtifacts); useCachedArtifacts.Get() != nil && *useCachedArtifacts.Get() {
			scanInfo.UseArtifactsFrom = getter.DefaultLocalStore // Load files from cache (this will prevent kubescape fom downloading the artifacts every time)
		}
	}

	// KeepLocal
	if scanRequest.KeepLocal != nil {
		if keepLocal := cautils.NewBoolPtr(scanRequest.KeepLocal); keepLocal.Get() != nil {
			scanInfo.Local = *keepLocal.Get() // Load files from cache (this will prevent kubescape fom downloading the artifacts every time)
		}
	}

	// submit
	if scanRequest.Submit != nil {
		if submit := cautils.NewBoolPtr(scanRequest.Submit); submit.Get() != nil {
			scanInfo.Submit = *submit.Get()
		}
	}

	// host scanner
	if scanRequest.HostScanner != nil {
		scanInfo.HostSensorEnabled = cautils.NewBoolPtr(scanRequest.HostScanner)
	}

	return scanInfo
}

func setTargetInScanInfo(scanRequest *utilsmetav1.PostScanRequest, scanInfo *cautils.ScanInfo) {
	// remove empty targets from slice
	scanRequest.TargetNames = slices.Filter(nil, scanRequest.TargetNames, func(e string) bool { return e != "" })

	if scanRequest.TargetType != "" && len(scanRequest.TargetNames) > 0 {
		if strings.EqualFold(string(scanRequest.TargetType), string(apisv1.KindFramework)) {
			scanRequest.TargetType = apisv1.KindFramework
			scanInfo.FrameworkScan = true
			scanInfo.ScanAll = false
			if cautils.StringInSlice(scanRequest.TargetNames, "all") != cautils.ValueNotFound { // if scan all frameworks
				scanRequest.TargetNames = []string{}
				scanInfo.ScanAll = true
			}
		} else if strings.EqualFold(string(scanRequest.TargetType), string(apisv1.KindControl)) {
			scanRequest.TargetType = apisv1.KindControl
			scanInfo.ScanAll = false
		} else {
			// unknown policy kind - set scan all
			scanInfo.FrameworkScan = true
			scanInfo.ScanAll = true
			scanRequest.TargetNames = []string{}
		}
		scanInfo.SetPolicyIdentifiers(scanRequest.TargetNames, scanRequest.TargetType)
	} else {
		scanInfo.FrameworkScan = true
		scanInfo.ScanAll = true
	}
}
