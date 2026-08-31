package scan

import (
	"fmt"
	"io"

	"github.com/kubescape/kubescape/v4/cmd/shared"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/meta"
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
)

// The workload identifier grammar is shared with the MCP server, which cannot
// import cmd/scan without pulling in cobra and the whole command tree, so it
// lives in core/cautils/workloadidentifier.go. These aliases keep the call
// sites below unchanged.
//
// ErrInvalidWorkloadIdentifier is aliased rather than redeclared on purpose:
// callers compare against it by identity, which a second errors.New carrying
// the same message would not satisfy.
var (
	ErrInvalidWorkloadIdentifier  = cautils.ErrInvalidWorkloadIdentifier
	parseWorkloadIdentifierString = cautils.ParseWorkloadIdentifierString
	validateWorkloadIdentifier    = cautils.ValidateWorkloadIdentifier
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
			ctx, cancel := deriveTimeoutContext(scanInfo, ks)
			defer cancel()

			if err := validateWorkloadArgs(args, scanInfo); err != nil {
				return err
			}
			if err := shared.ValidateCommonScanFlags(cmd, scanInfo, shared.ScanFormats); err != nil {
				return err
			}
			if err := validateThresholdsOnly(scanInfo); err != nil {
				return err
			}
			if scanInfo.LabelSelector != "" {
				return fmt.Errorf("--label-selector is not supported for workload scans: the named resource is fetched by identity, not by label")
			}
			namespace, kind, name, workloadAPIVersion, err := parseWorkloadIdentifierString(args[0])
			if err != nil {
				return fmt.Errorf("invalid input: %w", err)
			}

			if namespace != "" && scanInfo.Namespace == "" {
				scanInfo.Namespace = namespace
			}

			cleanup, err := prepareWorkloadInput(cmd.InOrStdin(), args, scanInfo)
			if err != nil {
				return err
			}
			defer cleanup()

			if apiVersion == "" {
				apiVersion = workloadAPIVersion
			}

			policyIdentifiers := setWorkloadScanInfo(scanInfo, kind, name, apiVersion)
			if err := validateCombinedImageScanFlags(scanInfo); err != nil {
				return err
			}

			results, err := ks.ScanContext(ctx, scanInfo, policyIdentifiers)
			if err != nil {
				return err
			}

			if err = results.HandleResults(ctx, scanInfo); err != nil {
				return err
			}

			if results.GetComplianceScore() < float32(scanInfo.ComplianceThreshold) {
				return fmt.Errorf("scan compliance-score is below permitted threshold: %.2f (compliance-threshold: %.2f)", results.GetComplianceScore(), scanInfo.ComplianceThreshold)
			}

			if err := enforceSeverityThresholds(&results.GetData().Report.SummaryDetails, scanInfo); err != nil {
				return err
			}
			if scanInfo.ScanImages {
				if err := enforceImageSeverityThresholds(results.ImageScanData, scanInfo); err != nil {
					return err
				}
			}
			if err := enforceCoverageThreshold(results.GetData().ScanCoverage, len(results.GetData().Report.SummaryDetails.Controls), scanInfo); err != nil {
				return err
			}
			if err := enforcePolicyDegradation(results.GetData().ScanCoverage, scanInfo); err != nil {
				return err
			}

			return enforceBaselineDrift(ctx, results, scanInfo)
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

	if scanInfo.FilePath != "" && len(args) > 1 {
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
	return prepareScanLocalInput(stdin, args, scanInfo, scanLocalInputOptions{
		FirstInputArg:    1,
		FilePath:         scanInfo.FilePath,
		RejectMixedStdin: true,
	})
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
