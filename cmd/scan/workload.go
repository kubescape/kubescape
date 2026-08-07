package scan

import (
	"errors"
	"fmt"
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

  # Scan a workload in a specific namespace
  %[1]s scan workload <kind>[.<version>[.<group>]]/<name> --namespace <namespace>

  # Scan a workload from a file path
  %[1]s scan workload <kind>[.<version>[.<group>]]/<name> --file-path <file path>
  
  # Scan a workload from a helm-chart template
  %[1]s scan workload <kind>[.<version>[.<group>]]/<name> --chart-path <chart path> --file-path <file path>


`, cautils.ExecName())

	ErrInvalidWorkloadIdentifier = errors.New("invalid workload identifier, expected <kind>[.<version>[.<group>]]/<name>")
)

// controlCmd represents the control command
func getWorkloadCmd(ks meta.IKubescape, scanInfo *cautils.ScanInfo) *cobra.Command {
	workloadCmd := &cobra.Command{
		Use:     "workload <kind>[.<version>[.<group>]]/<name> [`<glob pattern>`/`-`] [flags]",
		Short:   "Scan a workload for misconfigurations and image vulnerabilities",
		Example: workloadExample,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("usage: <kind>[.<version>[.<group>]]/<name> [`<glob pattern>`/`-`] [flags]")
			}

			// Looks strange, a bug maybe????
			if scanInfo.ChartPath != "" && scanInfo.FilePath == "" {
				return fmt.Errorf("usage: --chart-path <chart path> --file-path <file path>")
			}

			return validateWorkloadIdentifier(args[0])
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			defer applyTimeout(scanInfo, ks)()

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
			namespace, kind, name, apiVersion, err := parseWorkloadIdentifierString(args[0])
			if err != nil {
				return fmt.Errorf("invalid input: %w", err)
			}

			if namespace != "" && scanInfo.Namespace == "" {
				scanInfo.Namespace = namespace
			}

			policyIdentifiers := setWorkloadScanInfo(scanInfo, apiVersion, kind, name)

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

	return workloadCmd
}

func setWorkloadScanInfo(scanInfo *cautils.ScanInfo, apiVersion string, kind string, name string) []cautils.PolicyIdentifier {
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

	if scanInfo.FilePath != "" {
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
