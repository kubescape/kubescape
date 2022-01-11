package cautils

import (
	"fmt"
	"path/filepath"

	"github.com/armosec/k8s-interface/k8sinterface"
	"github.com/armosec/kubescape/cautils/getter"
	"github.com/armosec/opa-utils/reporthandling"
)

const (
	ScanCluster    string = "cluster"
	ScanLocalFiles string = "yaml"
)

type BoolPtrFlag struct {
	valPtr *bool
}

func (bpf *BoolPtrFlag) Type() string {
	return "bool"
}

func (bpf *BoolPtrFlag) String() string {
	if bpf.valPtr != nil {
		return fmt.Sprintf("%v", *bpf.valPtr)
	}
	return ""
}
func (bpf *BoolPtrFlag) Get() *bool {
	return bpf.valPtr
}

func (bpf *BoolPtrFlag) SetBool(val bool) {
	bpf.valPtr = &val
}

func (bpf *BoolPtrFlag) Set(val string) error {
	switch val {
	case "true":
		bpf.SetBool(true)
	case "false":
		bpf.SetBool(false)
	}
	return nil
}

type ScanInfo struct {
	Getters
	PolicyIdentifier   []reporthandling.PolicyIdentifier
	UseExceptions      string      // Load file with exceptions configuration
	ControlsInputs     string      // Load file with inputs for controls
	UseFrom            []string    // Load framework from local file (instead of download). Use when running offline
	UseDefault         bool        // Load framework from cached file (instead of download). Use when running offline
	VerboseMode        bool        // Display all of the input resources and not only failed resources
	Format             string      // Format results (table, json, junit ...)
	Output             string      // Store results in an output file, Output file name
	ExcludedNamespaces string      // used for host sensor namespace
	IncludeNamespaces  string      // DEPRECATED?
	InputPatterns      []string    // Yaml files input patterns
	Silent             bool        // Silent mode - Do not print progress logs
	FailThreshold      uint16      // Failure score threshold
	Submit             bool        // Submit results to Armo BE
	HostSensor         BoolPtrFlag // Deploy ARMO K8s host sensor to collect data from certain controls
	Local              bool        // Do not submit results
	Account            string      // account ID
	FrameworkScan      bool        // false if scanning control
	ScanAll            bool        // true if scan all frameworks
	ClusterName        string
}

type Getters struct {
	ExceptionsGetter     getter.IExceptionsGetter
	ControlsInputsGetter getter.IControlsInputsGetter
	PolicyGetter         getter.IPolicyGetter
}

func (scanInfo *ScanInfo) Init() {
	scanInfo.setUseFrom()
	scanInfo.setUseExceptions()
	scanInfo.setOutputFile()
	scanInfo.setClusterContextName()

}

func (scanInfo *ScanInfo) setClusterContextName() {
	k8sinterface.SetClusterContextName(scanInfo.ClusterName)
}

func (scanInfo *ScanInfo) setUseExceptions() {
	if scanInfo.UseExceptions != "" {
		// load exceptions from file
		scanInfo.ExceptionsGetter = getter.NewLoadPolicy([]string{scanInfo.UseExceptions})
	} else {
		scanInfo.ExceptionsGetter = getter.GetArmoAPIConnector()
	}
}

func (scanInfo *ScanInfo) setUseFrom() {
	if scanInfo.UseDefault {
		for _, policy := range scanInfo.PolicyIdentifier {
			scanInfo.UseFrom = append(scanInfo.UseFrom, getter.GetDefaultPath(policy.Name+".json"))
		}
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

func (scanInfo *ScanInfo) GetScanningEnvironment() string {
	if len(scanInfo.InputPatterns) != 0 {
		return ScanLocalFiles
	}
	return ScanCluster
}

func (scanInfo *ScanInfo) SetPolicyIdentifiers(policies []string, kind reporthandling.NotificationPolicyKind) {
	for _, policy := range policies {
		if !scanInfo.contains(policy) {
			newPolicy := reporthandling.PolicyIdentifier{}
			newPolicy.Kind = kind // reporthandling.KindFramework
			newPolicy.Name = policy
			scanInfo.PolicyIdentifier = append(scanInfo.PolicyIdentifier, newPolicy)
		}
	}
}

func (scanInfo *ScanInfo) contains(policyName string) bool {
	for _, policy := range scanInfo.PolicyIdentifier {
		if policy.Name == policyName {
			return true
		}
	}
	return false
}
