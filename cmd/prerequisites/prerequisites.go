package prerequisites

import (
	"github.com/kubescape/kubescape/v3/core/meta"
	"github.com/kubescape/sizing-checker/pkg/sizingchecker"
	"github.com/spf13/cobra"
)

func GetPreReqCmd(ks meta.IKubescape) *cobra.Command {
	preReqCmd := &cobra.Command{
		Use:   "prerequisites",
		Short: "Check prerequisites for installing Kubescape Operator",
		Run: func(cmd *cobra.Command, args []string) {
			sizingchecker.RunSizingChecker()
		},
	}
	return preReqCmd
}
