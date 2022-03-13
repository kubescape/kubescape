package submit

import (
	"fmt"

	"github.com/armosec/kubescape/cautils/logger"
	"github.com/armosec/kubescape/core/meta"
	metav1 "github.com/armosec/kubescape/core/meta/datastructures/v1"

	"github.com/spf13/cobra"
)

func getExceptionsCmd(ks meta.IKubescape, submitInfo *metav1.Submit) *cobra.Command {
	return &cobra.Command{
		Use:   "exceptions <full path to exceptins file>",
		Short: "Submit exceptions to the Kubescape SaaS version",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("missing full path to exceptions file")
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			if err := ks.SubmitExceptions(submitInfo.Account, args[0]); err != nil {
				logger.L().Fatal(err.Error())
			}
		},
	}
}
