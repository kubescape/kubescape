package delete

import (
	"fmt"
	"strings"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/meta"
	v1 "github.com/kubescape/kubescape/v2/core/meta/datastructures/v1"
	"github.com/spf13/cobra"
)

func getExceptionsCmd(ks meta.IKubescape, deleteInfo *v1.Delete) *cobra.Command {
	return &cobra.Command{
		Use:     "exceptions <exception name>",
		Short:   fmt.Sprintf("Delete exceptions from Kubescape SaaS version. Run '%[1]s list exceptions' for all exceptions names", cautils.ExecName()),
		Example: deleteExceptionsExamples,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("missing exceptions names")
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {

			if err := flagValidationDelete(deleteInfo); err != nil {
				logger.L().Fatal(err.Error())
			}

			exceptionsNames := strings.Split(args[0], ";")
			if len(exceptionsNames) == 0 {
				logger.L().Fatal("missing exceptions names")
			}
			if err := ks.DeleteExceptions(&v1.DeleteExceptions{Credentials: deleteInfo.Credentials, Exceptions: exceptionsNames}); err != nil {
				logger.L().Fatal(err.Error())
			}
		},
	}
}

// Check if the flag entered are valid
func flagValidationDelete(deleteInfo *v1.Delete) error {

	// Validate the user's credentials
	return deleteInfo.Credentials.Validate()
}
