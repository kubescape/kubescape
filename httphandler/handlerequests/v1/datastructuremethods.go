package v1

import (
	"strings"

	"github.com/armosec/kubescape/core/cautils"
	"github.com/armosec/kubescape/core/cautils/getter"
)

func (scanRequest *PostScanRequest) ToScanInfo() *cautils.ScanInfo {
	scanInfo := cautils.ScanInfo{}
	scanInfo.Account = scanRequest.Account
	scanInfo.ExcludedNamespaces = strings.Join(scanRequest.ExcludedNamespaces, ",")
	scanInfo.IncludeNamespaces = strings.Join(scanRequest.IncludeNamespaces, ",")
	scanInfo.FailThreshold = scanRequest.FailThreshold // TODO - handle default

	scanInfo.Format = scanRequest.Format // TODO - handle default

	if scanRequest.UseCachedArtifacts {
		scanInfo.UseArtifactsFrom = getter.DefaultLocalStore // Load files from cache (this will prevent kubescape fom downloading the artifacts every time)
	}

	scanInfo.Local = scanRequest.KeepLocal
	scanInfo.Submit = scanRequest.Submit
	scanInfo.HostSensorEnabled.SetBool(scanRequest.HostScanner)

	return &scanInfo
}

/*
err := clihandler.ScanCliSetup(&scanInfo)
		if err != nil {
			logger.L().Fatal(err.Error())
		}
*/
