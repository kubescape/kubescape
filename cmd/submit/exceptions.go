package submit

import (
	"context"
	"fmt"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v2/core/meta"
	metav1 "github.com/kubescape/kubescape/v2/core/meta/datastructures/v1"

	"github.com/spf13/cobra"
)

func getExceptionsCmd(ks meta.IKubescape, submitInfo *metav1.Submit) *cobra.Command {
	return &cobra.Command{
		Use:   "exceptions <full path to exceptions file>",
		Short: "Submit exceptions to the Kubescape SaaS version",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("missing full path to exceptions file")
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {

			if err := flagValidationSubmit(submitInfo); err != nil {
				logger.L().Fatal(err.Error())
			}

			if err := ks.SubmitExceptions(context.TODO(), &submitInfo.Credentials, args[0]); err != nil {
				logger.L().Fatal(err.Error())
			}
		},
	}
}
