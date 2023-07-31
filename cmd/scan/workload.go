package scan

import (
	"context"
	"fmt"
	"strings"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/meta"
	v1 "github.com/kubescape/opa-utils/httpserver/apis/v1"

	"github.com/spf13/cobra"
)

var (
	workloadExample = fmt.Sprintf(`
  # Scan an workload
  %[1]s scan workload <kind>/<name>
	
  # Scan an workload in a specific namespace
  %[1]s scan workload <kind>/<name> --namespace <namespace>

  # Scan an workload from a file path
  %[1]s scan workload <kind>/<name> --file-path <file path>
  
  # Scan an workload from a helm-chart template
  %[1]s scan workload <kind>/<name> --chart-path <chart path>


`, cautils.ExecName())
)

var namespace string

// controlCmd represents the control command
func getWorkloadCmd(ks meta.IKubescape, scanInfo *cautils.ScanInfo) *cobra.Command {
	workloadCmd := &cobra.Command{
		Use:     "workload <kind>/<name> [`<glob pattern>`/`-`] [flags]",
		Short:   fmt.Sprint("The workload you wish to scan"),
		Example: workloadExample,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("usage: <kind>/<name>")
			}

			if scanInfo.ChartPath != "" && scanInfo.FilePath == "" {
				return fmt.Errorf("usage: --chart-path <chart path> --file-path <file path>")
			}

			wlIdentifier := strings.Split(args[0], "/")
			if len(wlIdentifier) != 2 || wlIdentifier[0] == "" || wlIdentifier[1] == "" {
				return fmt.Errorf("usage: <kind>/<name>")
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			var wlIdentifier string

			wlIdentifier += args[0]
			kind, name, err := parseWorkloadIdentifierString(wlIdentifier)
			if err != nil {
				logger.L().Fatal(err.Error())
			}

			scanInfo.WorkloadIdentifier = &cautils.WorkloadIdentifier{
				Namespace: namespace,
				Kind:      kind,
				Name:      name,
			}

			scanInfo.ScanAll = true
			scanInfo.ScanType = cautils.ScanTypeWorkload
			scanInfo.ScanImages = true
			scanInfo.UseFrom = []string{"/Users/danielgrunberger/armo/merge/release/workloadscan.json"}

			scanInfo.SetPolicyIdentifiers([]string{"workloadscan"}, v1.KindFramework)

			ctx := context.TODO()
			results, err := ks.Scan(ctx, scanInfo)
			if err != nil {
				logger.L().Fatal(err.Error())
			}

			if err = results.HandleResults(ctx); err != nil {
				logger.L().Fatal(err.Error())
			}

			return nil
		},
	}
	workloadCmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", "", "Namespace of the workload. Default will be empty.")
	workloadCmd.PersistentFlags().StringVar(&scanInfo.FilePath, "file-path", "", "Path to the workload file.")
	workloadCmd.PersistentFlags().StringVar(&scanInfo.ChartPath, "chart-path", "", "Path to the helm chart.")

	return workloadCmd
}

func parseWorkloadIdentifierString(workloadIdentifier string) (kind, name string, err error) {
	// workloadIdentifier is in the form of namespace/kind/name
	// example: default/Deployment/nginx-deployment
	x := strings.Split(workloadIdentifier, "/")
	if len(x) != 2 {
		return "", "", fmt.Errorf("invalid workload identifier")
	}

	return x[0], x[1], nil
}
