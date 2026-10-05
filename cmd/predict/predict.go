package predict

import (
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/spf13/cobra"
)

// GetPredictCmd returns the top-level "predict" command, which groups
// sub-commands that predict the impact of security policy enforcement
// without modifying the cluster.
func GetPredictCmd() *cobra.Command {
	predictCmd := &cobra.Command{
		Use:   "predict",
		Short: "Predict the impact of security policy enforcement",
		Long: `Predict which workloads would fail or break under security policy
enforcement without modifying the cluster. Sub-commands evaluate
workloads against known standards and report violations, compliance
levels, and migration readiness.`,
		Example: `  # Predict PSS compliance for a namespace
  ` + cautils.ExecName() + ` predict pss -n production

  # Predict PSS compliance for local manifest files
  ` + cautils.ExecName() + ` predict pss ./manifests/`,
	}

	predictCmd.AddCommand(getPSSCmd())

	return predictCmd
}
