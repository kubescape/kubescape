package scan

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/armosec/kubescape/v2/core/cautils"
	"github.com/armosec/kubescape/v2/core/cautils/logger"
	"github.com/armosec/kubescape/v2/core/cautils/logger/helpers"
	"github.com/armosec/kubescape/v2/core/meta"
	"github.com/armosec/opa-utils/reporthandling"
	"github.com/enescakir/emoji"
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

  # Scan kubernetes YAML manifest files (single file or glob)
  kubescape scan framework nsa *.yaml

  Run 'kubescape list frameworks' for the list of supported frameworks
`
)

func getFrameworkCmd(ks meta.IKubescape, scanInfo *cautils.ScanInfo) *cobra.Command {

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

			if err := flagValidationFramework(scanInfo); err != nil {
				return err
			}
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
						scanInfo.InputPatterns = []string{args[1]}
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

			results, err := ks.Scan(scanInfo)
			if err != nil {
				logger.L().Fatal(err.Error())
			}

			if err = results.HandleResults(); err != nil {
				logger.L().Fatal(err.Error())
			}
			if !scanInfo.VerboseMode {
				cautils.SimpleDisplay(os.Stderr, "%s  Run with '--verbose'/'-v' flag for detailed resources view\n\n", emoji.Detective)
			}
			if results.GetRiskScore() > float32(scanInfo.FailThreshold) {
				logger.L().Fatal("scan risk-score is above permitted threshold", helpers.String("risk-score", fmt.Sprintf("%.2f", results.GetRiskScore())), helpers.String("fail-threshold", fmt.Sprintf("%.2f", scanInfo.FailThreshold)))
			}
			return nil
		},
	}
}

func flagValidationFramework(scanInfo *cautils.ScanInfo) error {
	if scanInfo.Submit && scanInfo.Local {
		return fmt.Errorf("you can use `keep-local` or `submit`, but not both")
	}
	if 100 < scanInfo.FailThreshold || 0 > scanInfo.FailThreshold {
		return fmt.Errorf("bad argument: out of range threshold")
	}
	return nil
}
