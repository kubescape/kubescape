package v1

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/core/core"
)

func scan(scanRequest *PostScanRequest, scanID string) ([]byte, error) {
	scanInfo := getScanCommand(scanRequest, scanID)
	ks := core.NewKubescape()
	result, err := ks.Scan(scanInfo)
	if err != nil {
		f, e := os.Open(filepath.Join(FailedOutputDir, scanID))
		if e != nil {
			return []byte{}, fmt.Errorf("failed to scan. reason: '%s'. failed to save error in file. reason: %s", err.Error(), e.Error())
		}
		defer f.Close()
		f.Write([]byte(e.Error()))

	}
	result.HandleResults()
	b, err := result.ToJson()
	if err != nil {
		err = fmt.Errorf("failed to parse results to json, reason: %s", err.Error())
	}
	return b, err

}

func readResultsFile(fileID string) ([]byte, error) {
	if fileName := searchFile(fileID); fileName != "" {
		return os.ReadFile(fileName)
	}
	return nil, fmt.Errorf("file not found")
}

func removeResultDirs() {
	os.ReadDir(OutputDir)
	os.ReadDir(FailedOutputDir)
}
func removeResultsFile(fileID string) error {
	if fileName := searchFile(fileID); fileName != "" {
		return os.Remove(fileName)
	}
	return nil // no files found to delete
}
func searchFile(fileID string) string {
	if fileName, _ := findFile(OutputDir, fileID); fileName != "" {
		return fileName
	}
	if fileName, _ := findFile(FailedOutputDir, fileID); fileName != "" {
		return fileName
	}
	return ""
}

func findFile(targetDir string, fileName string) (string, error) {

	matches, err := filepath.Glob(targetDir + fileName)
	if err != nil {
		return "", err
	}

	if len(matches) != 0 {
		return matches[0], nil
	}
	return "", nil
}

func getScanCommand(scanRequest *PostScanRequest, scanID string) *cautils.ScanInfo {

	scanInfo := scanRequest.ToScanInfo()
	scanInfo.ReportID = scanID

	// *** start ***
	// TODO - support frameworks/controls and support scanning single frameworks/controls
	scanInfo.FrameworkScan = true
	scanInfo.ScanAll = true
	// *** end ***

	// *** start ***
	// DO NOT CHANGE
	scanInfo.Output = filepath.Join(OutputDir, scanID)
	// *** end ***

	return scanInfo
}
