package list

import (
	"context"
	"errors"
	"fmt"
	"strings"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/core"
	"github.com/kubescape/kubescape/v3/core/meta"
	v1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slices"
)

var (
	listExample = fmt.Sprintf(`
  # List default supported frameworks names
  %[1]s list frameworks
  
  # List all supported frameworks names
  %[1]s list frameworks --account <account id>
	
  # List all supported controls names with ids
  %[1]s list controls
  
  Control documentation:
  https://hub.armosec.io/docs/controls
`, cautils.ExecName())
)

func GetListCmd(ks meta.IKubescape) *cobra.Command {
	var listPolicies = v1.ListPolicies{}

	listCmd := &cobra.Command{
		Use:     "list <policy> [flags]",
		Short:   "List frameworks/controls will list the supported frameworks and controls",
		Long:    ``,
		Example: listExample,
		Args: func(cmd *cobra.Command, args []string) error {
			supported := strings.Join(core.ListSupportActions(), ",")

			if len(args) < 1 {
				return fmt.Errorf("policy type requeued, supported: %s", supported)
			}
			if !slices.Contains(core.ListSupportActions(), args[0]) {
				return fmt.Errorf("invalid parameter '%s'. Supported parameters: %s", args[0], supported)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {

			if err := flagValidationList(&listPolicies); err != nil {
				return err
			}

			if len(args) < 1 {
				return errors.New("no arguements provided")
			}

			listPolicies.Target = args[0]

			if err := ks.List(context.TODO(), &listPolicies); err != nil {
				logger.L().Fatal(err.Error())
			}
			return nil
		},
	}
	listCmd.PersistentFlags().StringVarP(&listPolicies.AccountID, "account", "", "", "Kubescape SaaS account ID. Default will load account ID from cache")
	listCmd.PersistentFlags().StringVarP(&listPolicies.AccessKey, "access-key", "", "", "Kubescape SaaS access key. Default will load access key from cache")
	listCmd.PersistentFlags().StringVar(&listPolicies.Format, "format", "pretty-print", "output format. supported: 'pretty-print'/'json'")
	listCmd.PersistentFlags().MarkDeprecated("id", "Control ID's are included in list outputs")

	return listCmd
}

// Check if the flag entered are valid
func flagValidationList(listPolicies *v1.ListPolicies) error {

	// Validate the user's credentials
	return cautils.ValidateAccountID(listPolicies.AccountID)
}
