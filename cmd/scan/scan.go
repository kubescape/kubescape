package scan

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	"github.com/kubescape/kubescape/v3/core/meta"
	v1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/spf13/cobra"
)

// ScanInfo holds the information required for scanning
type ScanInfo struct {
	AccountID              string   // Example: "123456789"
	AccessKey              string   // Example: "abcdefg"
	ControlsInputs         string   // Example: "/path/to/controls-config"
	UseExceptions          string   // Example: "/path/to/exceptions"
	UseArtifactsFrom       string   // Example: "/path/to/artifacts"
	ExcludedNamespaces     string   // Example: "kube-system,default"
	FailThreshold          float32  // Example: 90.5
	ComplianceThreshold    float32  // Example: 80.0
	FailThresholdSeverity  string   // Example: "high"
	Format                 string   // Example: "json"
	IncludeNamespaces      string   // Example: "namespace1,namespace2"
	Local                  bool     // Example: true
	Output                 string   // Example: "results.json"
	VerboseMode            bool     // Example: true
	View                   string   // Example: "security"
	UseDefault             bool     // Example: true
	UseFrom                []string // Example: ["/path/to/policy1", "/path/to/policy2"]
	HostSensorYamlPath     string   // Example: "/path/to/host-sensor.yaml"
	FormatVersion          string   // Example: "v2"
	CustomClusterName      string   // Example: "MyCluster"
	Submit                 bool     // Example: true
	OmitRawResources       bool     // Example: true
	PrintAttackTree        bool     // Example: true
	ScanImages             bool     // Example: true

	// New field for allowed sensitive key names
	SensitiveKeyNamesAllowed []string // Example: ["password", "token"]
}

var scanCmdExamples = fmt.Sprintf(`
  Scan command is for scanning an existing cluster or kubernetes manifest files based on pre-defined frameworks 
  
  # Scan current cluster
  %[1]s scan

  # Scan kubernetes manifest files 
  %[1]s scan .

  # Scan and save the results in the JSON format
  %[1]s scan --format json --output results.json

  # Display all resources
  %[1]s scan --verbose

  # Scan different clusters from the kubectl context 
  %[1]s scan --kube-context <kubernetes context>
`, cautils.ExecName())

// GetScanCommand returns the scan command
func GetScanCommand(ks meta.IKubescape) *cobra.Command {
	var scanInfo ScanInfo

	// scanCmd represents the scan command
	scanCmd := &cobra.Command{
		Use:     "scan",
		Short:   "Scan a Kubernetes cluster or YAML files for image vulnerabilities and misconfigurations",
		Long:    `The action you want to perform`,
		Example: scanCmdExamples,
		RunE: func(cmd *cobra.Command, args []string) error {
			if scanInfo.View == string(cautils.SecurityViewType) {
				setSecurityViewScanInfo(args, &scanInfo)

				return securityScan(scanInfo, ks)
			}

			if len(args) == 0 || (args[0] != "framework" && args[0] != "control") {
				return getFrameworkCmd(ks, &scanInfo).RunE(cmd, append([]string{strings.Join(getter.NativeFrameworks, ",")}, args...))
			}
			return nil
		},
		PostRun: func(cmd *cobra.Command, args []string) {
			// TODO - revert context
		},
	}

	// Add sensitiveKeyNamesAllowed parameter to the scanner
	scanCmd.PersistentFlags().StringSliceVar(&scanInfo.SensitiveKeyNamesAllowed, "sensitive-key-names-allowed", nil, "List of allowed sensitive key names")

	// Other existing flags...

	return scanCmd
}

func setSecurityViewScanInfo(args []string, scanInfo *ScanInfo) {
	if len(args) > 0 {
		scanInfo.SetScanType(cautils.ScanTypeRepo)
		scanInfo.InputPatterns = args
	} else {
		scanInfo.SetScanType(cautils.ScanTypeCluster)
	}
	scanInfo.SetPolicyIdentifiers([]string{"clusterscan", "mitre", "nsa"}, v1.KindFramework)
}

func securityScan(scanInfo ScanInfo, ks meta.IKubescape) error {

	ctx := context.TODO()

	results, err := ks.Scan(ctx, &scanInfo)
	if err != nil {
		return err
	}

	if err = results.HandleResults(ctx); err != nil {
		return err
	}

	enforceSeverityThresholds(results.GetData().Report.SummaryDetails.GetResourcesSeverityCounters(), &scanInfo, terminateOnExceedingSeverity)

	return nil
}
