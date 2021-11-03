package cautils

import (
	"io"
	"os"
	"path/filepath"

	"github.com/armosec/kubescape/cautils/getter"
	"github.com/armosec/opa-utils/reporthandling"
)

type ScanInfo struct {
	Getters
	PolicyIdentifier   []reporthandling.PolicyIdentifier
	UseExceptions      string   // Load file with exceptions configuration
	ControlsInputs     string   // Load file with inputs for controls
	UseFrom            []string // Load framework from local file (instead of download). Use when running offline
	UseDefault         bool     // Load framework from cached file (instead of download). Use when running offline
	Format             string   // Format results (table, json, junit ...)
	Output             string   // Store results in an output file, Output file name
	ExcludedNamespaces string   // DEPRECATED?
	InputPatterns      []string // Yaml files input patterns
	Silent             bool     // Silent mode - Do not print progress logs
	FailThreshold      uint16   // Failure score threshold
	Submit             bool     // Submit results to Armo BE
	Local              bool     // Do not submit results
	Account            string   // account ID
	FrameworkScan      bool     // false if scanning control
}

type Getters struct {
	ExceptionsGetter     getter.IExceptionsGetter
	ControlsInputsGetter getter.IControlsInputsGetter
	PolicyGetter         getter.IPolicyGetter
}

func (scanInfo *ScanInfo) Init() {
	scanInfo.setUseFrom()
	scanInfo.setUseExceptions()
	scanInfo.setAccountConfig()
	scanInfo.setOutputFile()
	scanInfo.setGetter()

}

func (scanInfo *ScanInfo) setUseExceptions() {
	if scanInfo.UseExceptions != "" {
		// load exceptions from file
		scanInfo.ExceptionsGetter = getter.NewLoadPolicy([]string{scanInfo.UseExceptions})
	} else {
		scanInfo.ExceptionsGetter = getter.GetArmoAPIConnector()
	}
}

func (scanInfo *ScanInfo) setAccountConfig() {
	if scanInfo.ControlsInputs != "" {
		// load account config from file
		scanInfo.ControlsInputsGetter = getter.NewLoadPolicy([]string{scanInfo.ControlsInputs})
	} else {
		scanInfo.ControlsInputsGetter = getter.GetArmoAPIConnector()
	}
}
func (scanInfo *ScanInfo) setUseFrom() {
	if scanInfo.UseDefault {
		for _, policy := range scanInfo.PolicyIdentifier {
			scanInfo.UseFrom = append(scanInfo.UseFrom, getter.GetDefaultPath(policy.Name+".json"))
		}
	}
}

func (scanInfo *ScanInfo) SetInputPatterns(args []string) error {
	if args[1] != "-" {
		scanInfo.InputPatterns = args[1:]
	} else { // store stout to file
		tempFile, err := os.CreateTemp(".", "tmp-kubescape*.yaml")
		if err != nil {
			return err
		}
		defer os.Remove(tempFile.Name())

		if _, err := io.Copy(tempFile, os.Stdin); err != nil {
			return err
		}
		scanInfo.InputPatterns = []string{tempFile.Name()}
	}
	return nil
}
func (scanInfo *ScanInfo) setGetter() {
	if len(scanInfo.UseFrom) > 0 {
		// load from file
		scanInfo.PolicyGetter = getter.NewLoadPolicy(scanInfo.UseFrom)
	} else {
		scanInfo.PolicyGetter = getter.NewDownloadReleasedPolicy()
	}
}

func (scanInfo *ScanInfo) setOutputFile() {
	if scanInfo.Output == "" {
		return
	}
	if scanInfo.Format == "json" {
		if filepath.Ext(scanInfo.Output) != ".json" {
			scanInfo.Output += ".json"
		}
	}
	if scanInfo.Format == "junit" {
		if filepath.Ext(scanInfo.Output) != ".xml" {
			scanInfo.Output += ".xml"
		}
	}
}

func (scanInfo *ScanInfo) ScanRunningCluster() bool {
	return len(scanInfo.InputPatterns) == 0
}
