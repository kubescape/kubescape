package v1

import (
	"encoding/json"

	"github.com/armosec/kubescape/clihandler"
)

func (handler *HTTPHandler) executeScanRequest(readBuffer []byte, scanID string) error {
	scanRequest := PostScanRequest{}
	if err := json.Unmarshal(readBuffer, &scanRequest); err != nil {
		return err
	}
	scanInfo := scanRequest.ToScanInfo()
	scanInfo.ReportID = scanID

	// *** start ***
	// TODO - support frameworks/controls and support scanning single frameworks/controls
	scanInfo.FrameworkScan = true
	scanInfo.ScanAll = true
	// *** end ***

	// *** start ***
	// DO NOT CHANGE
	scanInfo.Output = OutputDir
	// *** end ***

	scanInfo.Init()

	err := clihandler.ScanCliSetup(scanInfo)
	if err != nil {
		return err
	}
	return nil
}
