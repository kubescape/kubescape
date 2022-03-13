package scan

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/cautils/logger"
	"github.com/armosec/kubescape/core/core"
	"github.com/armosec/opa-utils/reporthandling"
	"github.com/spf13/cobra"
)

var (
	frameworkExample = `
  # Scan all frameworks and submit the results
  kubescape scan framework all --submit
  
  # Scan the NSA framework
  kubescape scan framework nsa
  
  # Scan the NSA and MITRE framework
  kubescape scan framework nsa,mitre
  
  # Scan all frameworks
  kubescape scan framework all

  # Scan kubernetes YAML manifest files
  kubescape scan framework nsa *.yaml

  Run 'kubescape list frameworks' for the list of supported frameworks
`
)

func getFrameworkCmd(scanInfo *cautils.ScanInfo) *cobra.Command {

	return &cobra.Command{
		Use:     "framework <framework names list> [`<glob pattern>`/`-`] [flags]",
		Short:   "The framework you wish to use. Run 'kubescape list frameworks' for the list of supported frameworks",
		Example: frameworkExample,
		Long:    "Execute a scan on a running Kubernetes cluster or `yaml`/`json` files (use glob) or `-` for stdin",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				frameworks := strings.Split(args[0], ",")
				if len(frameworks) > 1 {
					for _, framework := range frameworks {
						if framework == "" {
							return fmt.Errorf("usage: <framework-0>,<framework-1>")
						}
					}
				}
			} else {
				return fmt.Errorf("requires at least one framework name")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {

			flagValidationFramework(scanInfo)
			scanInfo.FrameworkScan = true

			var frameworks []string

			if len(args) == 0 { // scan all frameworks
				scanInfo.ScanAll = true
			} else {
				// Read frameworks from input args
				frameworks = strings.Split(args[0], ",")
				if cautils.StringInSlice(frameworks, "all") != cautils.ValueNotFound {
					scanInfo.ScanAll = true
					frameworks = []string{}
				}
				if len(args) > 1 {
					if len(args[1:]) == 0 || args[1] != "-" {
						scanInfo.InputPatterns = args[1:]
					} else { // store stdin to file - do NOT move to separate function !!
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
				}
			}
			scanInfo.FrameworkScan = true

			scanInfo.SetPolicyIdentifiers(frameworks, reporthandling.KindFramework)

			results, err := core.Scan(scanInfo)
			if err != nil {
				logger.L().Fatal(err.Error())
			}
			results.HandleResults()
			if results.GetRiskScore() > float32(scanInfo.FailThreshold) {
				return fmt.Errorf("scan risk-score %.2f is above permitted threshold %.2f", results.GetRiskScore(), scanInfo.FailThreshold)
			}
			return nil
		},
	}
}

// func init() {
// 	scanCmd.AddCommand(frameworkCmd)
// 	scanInfo = cautils.ScanInfo{}

// }

// func SetScanForFirstFramework(frameworks []string) []reporthandling.PolicyIdentifier {
// 	newPolicy := reporthandling.PolicyIdentifier{}
// 	newPolicy.Kind = reporthandling.KindFramework
// 	newPolicy.Name = frameworks[0]
// 	scanInfo.PolicyIdentifier = append(scanInfo.PolicyIdentifier, newPolicy)
// 	return scanInfo.PolicyIdentifier
// }

func flagValidationFramework(scanInfo *cautils.ScanInfo) {
	if scanInfo.Submit && scanInfo.Local {
		logger.L().Fatal("you can use `keep-local` or `submit`, but not both")
	}
	if 100 < scanInfo.FailThreshold {
		logger.L().Fatal("bad argument: out of range threshold")
	}
}
