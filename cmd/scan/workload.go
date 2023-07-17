package scan

import (
	"fmt"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/meta"

	"github.com/spf13/cobra"
)

var (
	workloadExample = fmt.Sprintf(`
  # Scan a workload
  %[1]s scan workload <kind>/<name>
  
  # Scan a workload in a specific namespace
  %[1]s scan workload <kind>/<name> --namespace <namespace>
  
`, cautils.ExecName())
)

func getWorkloadCMD(ks meta.IKubescape, scanInfo *cautils.ScanInfo) *cobra.Command {
	return &cobra.Command{
		Use:     "workloads <kind>/<name> [flags]",
		Short:   fmt.Sprintf("The workload you wish to scan", cautils.ExecName()),
		Example: workloadExample,
		Long:    "Execute a workload scan on a running Kubernetes cluster or `yaml`/`json` files (use glob) or `-` for stdin",
		Args: func(cmd *cobra.Command, args []string) error {
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {

			return nil
		},
	}
}
