package scan

import (
	"context"
	"errors"
	"fmt"
	"strings"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/meta"
	v1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/objectsenvelopes"

	"github.com/spf13/cobra"
)

var (
	workloadExample = fmt.Sprintf(`
  Scan a workload for misconfigurations and image vulnerabilities.

  # Scan an workload
  %[1]s scan workload <kind>/<name>
	
  # Scan an workload in a specific namespace
  %[1]s scan workload <kind>/<name> --namespace <namespace>

  # Scan an workload from a file path
  %[1]s scan workload <kind>/<name> --file-path <file path>
  
  # Scan an workload from a helm-chart template
  %[1]s scan workload <kind>/<name> --chart-path <chart path> --file-path <file path>


`, cautils.ExecName())

	ErrInvalidWorkloadIdentifier = errors.New("invalid workload identifier")
)

var namespace string

// controlCmd represents the control command
func getWorkloadCmd(ks meta.IKubescape, scanInfo *cautils.ScanInfo) *cobra.Command {
	workloadCmd := &cobra.Command{
		Use:     "workload <kind>/<name> [`<glob pattern>`/`-`] [flags]",
		Short:   "Scan a workload for misconfigurations and image vulnerabilities",
		Example: workloadExample,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("usage: <kind>/<name> [`<glob pattern>`/`-`] [flags]")
			}

			// Looks strange, a bug maybe????
			if scanInfo.ChartPath != "" && scanInfo.FilePath == "" {
				return fmt.Errorf("usage: --chart-path <chart path> --file-path <file path>")
			}

			return validateWorkloadIdentifier(args[0])
		},
		RunE: func(cmd *cobra.Command, args []string) error {

			kind, name, err := parseWorkloadIdentifierString(args[0])
			if err != nil {
				return fmt.Errorf("invalid input: %s", err.Error())
			}

			setWorkloadScanInfo(scanInfo, kind, name)

			// todo: add api version if provided
			ctx := context.TODO()
			results, err := ks.Scan(ctx, scanInfo)
			if err != nil {
				logger.L().Fatal(err.Error())
			}

			if err = results.HandleResults(ctx); err != nil {
				logger.L().Fatal(err.Error())
			}

			enforceSeverityThresholds(results.GetData().Report.SummaryDetails.GetResourcesSeverityCounters(), scanInfo, terminateOnExceedingSeverity)

			return nil
		},
	}
	workloadCmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", "", "Namespace of the workload. Default will be empty.")
	workloadCmd.PersistentFlags().StringVar(&scanInfo.FilePath, "file-path", "", "Path to the workload file.")
	workloadCmd.PersistentFlags().StringVar(&scanInfo.ChartPath, "chart-path", "", "Path to the helm chart the workload is part of. Must be used with --file-path.")

	return workloadCmd
}

func setWorkloadScanInfo(scanInfo *cautils.ScanInfo, kind string, name string) {
	scanInfo.SetScanType(cautils.ScanTypeWorkload)
	scanInfo.ScanImages = true

	scanInfo.ScanObject = &objectsenvelopes.ScanObject{}
	scanInfo.ScanObject.SetNamespace(namespace)
	scanInfo.ScanObject.SetKind(kind)
	scanInfo.ScanObject.SetName(name)

	scanInfo.SetPolicyIdentifiers([]string{"workloadscan"}, v1.KindFramework)

	if scanInfo.FilePath != "" {
		scanInfo.InputPatterns = []string{scanInfo.FilePath}
	}
}

func validateWorkloadIdentifier(workloadIdentifier string) error {
	// workloadIdentifier is in the form of kind/name
	x := strings.Split(workloadIdentifier, "/")
	if len(x) != 2 || x[0] == "" || x[1] == "" {
		return ErrInvalidWorkloadIdentifier
	}

	return nil
}

func parseWorkloadIdentifierString(workloadIdentifier string) (kind, name string, err error) {
	// workloadIdentifier is in the form of namespace/kind/name
	// example: default/Deployment/nginx-deployment
	x := strings.Split(workloadIdentifier, "/")
	if len(x) != 2 {
		return "", "", ErrInvalidWorkloadIdentifier
	}

	return x[0], x[1], nil
}
