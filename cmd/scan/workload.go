package scan

import (
	"context"
	"fmt"
	"strings"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/meta"

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

			wlIdentifier := strings.Split(args[0], "/")
			if len(wlIdentifier) != 2 || wlIdentifier[0] == "" || wlIdentifier[1] == "" {
				return fmt.Errorf("usage: <kind>/<name>")
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			var wlIdentifier string

			if namespace != "" {
				wlIdentifier = fmt.Sprintf("%s/", namespace)
			}
			wlIdentifier += args[0]

			scanInfo.WorkloadIdentifier = wlIdentifier

			ctx := context.TODO()
			_, err := ks.Scan(ctx, scanInfo)
			if err != nil {
				logger.L().Fatal(err.Error())
			}

			return nil
		},
	}
	workloadCmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", "", "Namespace of the workload. Default will be empty.")

	return workloadCmd
}
