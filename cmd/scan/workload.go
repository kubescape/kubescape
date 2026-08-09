package scan

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v3/cmd/shared"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/meta"
	v1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/spf13/cobra"
)

var (
	workloadExample = fmt.Sprintf(`
  Scan a workload for misconfigurations and image vulnerabilities.

  # Scan a workload
  %[1]s scan workload <kind>[.<version>[.<group>]]/<name>
	
  # Scan a specific kind, version, and group
  %[1]s scan workload Deployment.v1.apps/nginx

  # Scan an workload from a file path
  %[1]s scan workload <kind>/<name> --file-path <file path>

  # Scan a workload from local manifests
  %[1]s scan workload <kind>[.<version>[.<group>]]/<name> ./manifests

  # Scan a workload from a specific file path
  %[1]s scan workload <kind>[.<version>[.<group>]]/<name> --file-path <file path>
  # Scan an workload with a specific API version
  %[1]s scan workload <kind>/<name> --api-version <api version>
  
  # Scan a workload from a helm-chart template
  %[1]s scan workload <kind>[.<version>[.<group>]]/<name> --chart-path <chart path> --file-path <file path>


`, cautils.ExecName())

	ErrInvalidWorkloadIdentifier = errors.New("invalid workload identifier, expected <kind>[.<version>[.<group>]]/<name>")
)

// controlCmd represents the control command
func getWorkloadCmd(ks meta.IKubescape, scanInfo *cautils.ScanInfo) *cobra.Command {
	var apiVersion string

	workloadCmd := &cobra.Command{
		Use:     "workload <kind>[.<version>[.<group>]]/<name> [`<glob pattern>`/`-`] [flags]",
		Short:   "Scan a workload for misconfigurations and image vulnerabilities",
		Example: workloadExample,
		Args: func(cmd *cobra.Command, args []string) error {
			return validateWorkloadArgs(args, scanInfo)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			defer applyTimeout(scanInfo, ks)()

			if err := validateWorkloadArgs(args, scanInfo); err != nil {
				return err
			}
			if scanInfo.FailThresholdSeverity != "" {
				if err := shared.ValidateSeverity(scanInfo.FailThresholdSeverity); err != nil {
					return err
				}
			}
			if f := cmd.InheritedFlags().Lookup("format"); f != nil && f.Changed && scanInfo.Format == "" {
				return fmt.Errorf("format cannot be empty, supported formats: pretty-printer, json, junit, prometheus, pdf, html, sarif, gitlab-sast")
			}
			if err := shared.ValidateScanFormat(scanInfo.Format, shared.ScanFormats); err != nil {
				return err
			}
			if err := validateThresholdsOnly(scanInfo); err != nil {
				return err
			}
			namespace, kind, name, workloadAPIVersion, err := parseWorkloadIdentifierString(args[0])
			if err != nil {
				return fmt.Errorf("invalid input: %w", err)
			}

			if namespace != "" && scanInfo.Namespace == "" {
				scanInfo.Namespace = namespace
			}

			cleanup, err := prepareWorkloadInput(os.Stdin, args, scanInfo)
			if err != nil {
				return err
			}
			defer cleanup()

			if apiVersion == "" {
				apiVersion = workloadAPIVersion
			}

			policyIdentifiers := setWorkloadScanInfo(scanInfo, kind, name, apiVersion)

			results, err := ks.Scan(scanInfo, policyIdentifiers)
			if err != nil {
				logger.L().Fatal(err.Error())
			}

			if err = results.HandleResults(ks.Context(), scanInfo); err != nil {
				logger.L().Fatal(err.Error())
			}

			enforceSeverityThresholds(results.GetData().Report.SummaryDetails.GetResourcesSeverityCounters(), scanInfo, terminateOnExceedingSeverity)
			enforceCoverageThreshold(results.GetData().ScanCoverage, len(results.GetData().Report.SummaryDetails.Controls), scanInfo)
			enforcePolicyDegradation(results.GetData().ScanCoverage, scanInfo)

			return nil
		},
	}

	workloadCmd.PersistentFlags().StringVarP(&scanInfo.Namespace, "namespace", "n", "", "Namespace of the workload. Default will be empty.")
	workloadCmd.PersistentFlags().StringVar(&scanInfo.FilePath, "file-path", "", "Path to the workload file.")
	workloadCmd.PersistentFlags().StringVar(&scanInfo.ChartPath, "chart-path", "", "Path to the helm chart the workload is part of. Must be used with --file-path.")
	workloadCmd.PersistentFlags().StringVar(&apiVersion, "api-version", "", "API version of the workload (e.g. apps/v1). Default will be empty.")

	return workloadCmd
}

func validateWorkloadArgs(args []string, scanInfo *cautils.ScanInfo) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: <kind>[.<version>[.<group>]]/<name> [`<glob pattern>`/`-`] [flags]")
	}

	if scanInfo.ChartPath != "" && scanInfo.FilePath == "" {
		return fmt.Errorf("usage: --chart-path <chart path> --file-path <file path>")
	}

	if scanInfo.ChartPath == "" && scanInfo.FilePath != "" && len(args) > 1 {
		return fmt.Errorf("usage: use either --file-path or positional input paths, not both")
	}

	for _, arg := range args[1:] {
		if arg == "-" && len(args) > 2 {
			return fmt.Errorf("usage: stdin input '-' cannot be combined with other input paths")
		}
	}

	return validateWorkloadIdentifier(args[0])
}

func prepareWorkloadInput(stdin io.Reader, args []string, scanInfo *cautils.ScanInfo) (func(), error) {
	cleanup := func() {}
	if len(args) > 1 {
		if args[1] == "-" {
			tempFile, err := os.CreateTemp("", "tmp-kubescape*.yaml")
			if err != nil {
				return cleanup, err
			}
			cleanup = func() {
				_ = os.Remove(tempFile.Name())
			}

			if _, err := io.Copy(tempFile, stdin); err != nil {
				_ = tempFile.Close()
				cleanup()
				return func() {}, err
			}
			if err := tempFile.Close(); err != nil {
				cleanup()
				return func() {}, err
			}
			scanInfo.InputPatterns = []string{tempFile.Name()}
			return cleanup, nil
		}

		scanInfo.InputPatterns = args[1:]
		return cleanup, nil
	}

	if scanInfo.FilePath != "" {
		scanInfo.InputPatterns = []string{scanInfo.FilePath}
	}
	return cleanup, nil
}

func setWorkloadScanInfo(scanInfo *cautils.ScanInfo, kind string, name string, apiVersion string) []cautils.PolicyIdentifier {
	scanInfo.SetScanType(cautils.ScanTypeWorkload)
	scanInfo.ScanImages = true

	scanInfo.ScanObject = &objectsenvelopes.ScanObject{}
	scanInfo.ScanObject.SetNamespace(scanInfo.Namespace)
	if apiVersion != "" {
		scanInfo.ScanObject.SetApiVersion(apiVersion)
	}
	scanInfo.ScanObject.SetKind(kind)
	scanInfo.ScanObject.SetName(name)

	policyIdentifiers := cautils.BuildPolicyIdentifiers([]string{"workloadscan", "allcontrols"}, v1.KindFramework)

	if scanInfo.FilePath != "" && len(scanInfo.InputPatterns) == 0 {
		scanInfo.InputPatterns = []string{scanInfo.FilePath}
	}

	return policyIdentifiers
}

func validateWorkloadIdentifier(workloadIdentifier string) error {
	_, _, _, _, err := parseWorkloadIdentifierString(workloadIdentifier)
	return err
}

func parseWorkloadIdentifierString(workloadIdentifier string) (namespace, kind, name, apiVersion string, err error) {
	// workloadIdentifier is in the form of kind/name or namespace/kind/name
	// example: default/Deployment/nginx-deployment
	x := strings.Split(workloadIdentifier, "/")
	if len(x) == 2 {
		if x[0] == "" || x[1] == "" {
			return "", "", "", "", ErrInvalidWorkloadIdentifier
		}
		parsedKind, parsedApiVersion, err := parseKindAndApiVersion(x[0])
		if err != nil {
			return "", "", "", "", err
		}
		return "", parsedKind, x[1], parsedApiVersion, nil
	}
	if len(x) == 3 {
		if x[0] == "" || x[1] == "" || x[2] == "" {
			return "", "", "", "", ErrInvalidWorkloadIdentifier
		}
		parsedKind, parsedApiVersion, err := parseKindAndApiVersion(x[1])
		if err != nil {
			return "", "", "", "", err
		}
		return x[0], parsedKind, x[2], parsedApiVersion, nil
	}

	return "", "", "", "", ErrInvalidWorkloadIdentifier
}

var apiVersionPattern = regexp.MustCompile(`^v\d+((alpha|beta)\d+)?$`)

func parseKindAndApiVersion(kindStr string) (kind, apiVersion string, err error) {
	parts := strings.Split(kindStr, ".")
	if len(parts) == 1 {
		return kindStr, "", nil
	}

	// Reject empty components
	for _, part := range parts {
		if part == "" {
			return "", "", fmt.Errorf("%w: empty component in %q", ErrInvalidWorkloadIdentifier, kindStr)
		}
	}

	if !apiVersionPattern.MatchString(parts[1]) {
		return "", "", fmt.Errorf("%w: %q is not a valid API version in %q", ErrInvalidWorkloadIdentifier, parts[1], kindStr)
	}

	if len(parts) >= 3 {
		group := strings.Join(parts[2:], ".")
		return parts[0], group + "/" + parts[1], nil // kind.version.group -> group/version
	}
	return parts[0], parts[1], nil // kind.version -> version
}
