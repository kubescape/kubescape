package v1

import (
	"strings"

	"github.com/armosec/kubescape/cautils"
)

func (scanRequest *PostScanRequest) ToScanInfo() *cautils.ScanInfo {
	scanInfo := cautils.ScanInfo{}
	scanInfo.Account = scanRequest.Account
	scanInfo.ExcludedNamespaces = strings.Join(scanRequest.ExcludedNamespaces, ",")
	scanInfo.IncludeNamespaces = strings.Join(scanRequest.IncludeNamespaces, ",")
	scanInfo.FailThreshold = scanRequest.FailThreshold // TODO - handle default

	scanInfo.Format = scanRequest.Format // TODO - handle default

	scanInfo.Local = scanRequest.KeepLocal
	scanInfo.Submit = scanRequest.Submit
	scanInfo.HostSensorEnabled.SetBool(scanRequest.HostSensor)

	return &scanInfo
}

/*
err := clihandler.ScanCliSetup(&scanInfo)
		if err != nil {
			logger.L().Fatal(err.Error())
		}
*/
