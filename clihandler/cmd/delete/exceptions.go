package delete

import (
	"fmt"
	"strings"

	"github.com/armosec/kubescape/cautils/logger"
	"github.com/armosec/kubescape/clihandler"
	"github.com/spf13/cobra"
)

func getExceptionsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "exceptions <exception name>",
		Short:   "Delete exceptions from Kubescape SaaS version. Run 'kubescape list exceptions' for all exceptions names",
		Example: deleteExceptionsExamples,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("missing exceptions names")
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			exceptionsNames := strings.Split(args[0], ";")
			if len(exceptionsNames) == 0 {
				logger.L().Fatal("missing exceptions names")
			}
			if err := clihandler.DeleteExceptions(deleteInfo.Account, exceptionsNames); err != nil {
				logger.L().Fatal(err.Error())
			}
		},
	}
}
