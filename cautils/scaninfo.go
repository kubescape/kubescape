package cautils

import (
	"path/filepath"

	"github.com/armosec/kubescape/cautils/getter"
	"github.com/armosec/kubescape/cautils/opapolicy"
)

type ScanInfo struct {
	Getters
	PolicyIdentifier   opapolicy.PolicyIdentifier
	UseExceptions      string
	UseFrom            string
	UseDefault         bool
	Format             string
	Output             string
	ExcludedNamespaces string
	InputPatterns      []string
	Silent             bool
	FailThreshold      uint16
}

type Getters struct {
	ExceptionsGetter getter.IPolicyGetter
	PolicyGetter     getter.IPolicyGetter
}

func (scanInfo *ScanInfo) Init() {
	scanInfo.setUseFrom()
	scanInfo.setUseExceptions()
	scanInfo.setOutputFile()
	scanInfo.setGetter()

}

func (scanInfo *ScanInfo) setUseExceptions() {
	if scanInfo.UseExceptions != "" {
		// load exceptions from file
		scanInfo.ExceptionsGetter = getter.NewLoadPolicy(scanInfo.UseExceptions)
	} else {
		scanInfo.ExceptionsGetter = getter.NewArmoAPI()
	}

}
func (scanInfo *ScanInfo) setUseFrom() {
	if scanInfo.UseFrom != "" {
		return
	}
	if scanInfo.UseDefault {
		scanInfo.UseFrom = getter.GetDefaultPath(scanInfo.PolicyIdentifier.Name)
	}

}
func (scanInfo *ScanInfo) setGetter() {
	if scanInfo.UseFrom != "" {
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
		if filepath.Ext(scanInfo.Output) != "json" {
			scanInfo.Output += ".json"
		}
	}
	if scanInfo.Format == "junit" {
		if filepath.Ext(scanInfo.Output) != "xml" {
			scanInfo.Output += ".xml"
		}
	}
}

func (scanInfo *ScanInfo) ScanRunningCluster() bool {
	return len(scanInfo.InputPatterns) == 0
}
