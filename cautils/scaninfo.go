package cautils

import (
	"path/filepath"

	"github.com/armosec/kubescape/cautils/getter"
	"github.com/armosec/kubescape/cautils/opapolicy"
)

type ScanInfo struct {
	Getters
	PolicyIdentifier   opapolicy.PolicyIdentifier
	UseExceptions      string   // Load exceptions configuration
	UseFrom            string   // Load framework from local file (instead of download). Use when running offline
	UseDefault         bool     // Load framework from cached file (instead of download). Use when running offline
	Format             string   // Format results (table, json, junit ...)
	Output             string   // Store results in an output file, Output file name
	ExcludedNamespaces string   // DEPRECATED?
	InputPatterns      []string // Yaml files input patterns
	Silent             bool     // Silent mode - Do not print progress logs
	FailThreshold      uint16   // Failure score threshold
	DoNotSendResults   bool     // DEPRECATED
	Submit             bool     // Submit results to Armo BE
	Local              bool     // Do not submit results
	Account            string   // account ID
}

type Getters struct {
	ExceptionsGetter getter.IExceptionsGetter
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
		scanInfo.ExceptionsGetter = getter.GetArmoAPIConnector()
	}

}
func (scanInfo *ScanInfo) setUseFrom() {
	if scanInfo.UseFrom != "" {
		return
	}
	if scanInfo.UseDefault {
		scanInfo.UseFrom = getter.GetDefaultPath(scanInfo.PolicyIdentifier.Name + ".json")
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

// func (scanInfo *ScanInfo) ConnectedToCluster(k8s k8sinterface.) bool {
// 	_, err := k8s.KubernetesClient.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
// 	return err == nil
// }
