package list

import (
	"fmt"
	"slices"
	"strings"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/core"
	"github.com/kubescape/kubescape/v4/core/meta"
	v1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/spf13/cobra"
)

var (
	listExample = fmt.Sprintf(`
  # List default supported frameworks names
  %[1]s list frameworks
  
  # List all supported frameworks names
  %[1]s list frameworks --account <account id>
	
  # List all supported controls names with ids
  %[1]s list controls

  # List controls in a framework, optionally narrowed by text
  %[1]s list controls --framework NSA --search container

  # Show the configurable inputs a scan evaluates controls against
  %[1]s list controls-config

  # Show the inputs a scan would use with a local controls-config override
  %[1]s list controls-config --controls-config ./controls-inputs.json
  
  Control documentation:
  https://kubescape.io/docs/controls/
`, cautils.ExecName())
)

func GetListCmd(ks meta.IKubescape) *cobra.Command {
	var listPolicies = v1.ListPolicies{}

	listCmd := &cobra.Command{
		Use:     "list <policy> [flags]",
		Short:   "List the supported frameworks, controls and control configuration",
		Long:    ``,
		Example: listExample,
		Args: func(cmd *cobra.Command, args []string) error {
			supported := strings.Join(core.ListSupportActions(), ",")

			if len(args) < 1 {
				return fmt.Errorf("policy type required, supported: %s", supported)
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

			listPolicies.Target = args[0]
			if err := validateControlListFilters(listPolicies.Target, listPolicies.ControlFilters); err != nil {
				return err
			}

			result, err := ks.List(&listPolicies)
			if err != nil {
				return err
			}
			if err := core.PrintListResult(ks.Context(), result, listPolicies.Target, listPolicies.Format); err != nil {
				return err
			}
			return nil
		},
	}
	listCmd.PersistentFlags().StringVarP(&listPolicies.AccountID, "account", "", "", "Kubescape SaaS account ID. Default will load account ID from cache")
	listCmd.PersistentFlags().StringVarP(&listPolicies.AccessKey, "access-key", "", "", "Kubescape SaaS access key. Default will load access key from cache")
	listCmd.PersistentFlags().StringVarP(&listPolicies.Format, "format", "f", "pretty-print", "output format. supported: 'pretty-print'/'json'/'yaml'/'csv'")
	listCmd.PersistentFlags().StringVar(&listPolicies.ControlsInputs, "controls-config", "", "Path to a controls-config file, to show the inputs a scan would use with it. Only applies to 'controls-config'")
	listCmd.PersistentFlags().StringVar(&listPolicies.ControlFilters.Framework, "framework", "", "Only applies to 'controls'. Return controls that belong to this framework")
	listCmd.PersistentFlags().StringVar(&listPolicies.ControlFilters.Search, "search", "", "Only applies to 'controls'. Case-insensitive match against control ID, name, or framework")

	// Deprecated flags
	var dummyID bool
	listCmd.PersistentFlags().BoolVar(&dummyID, "id", false, "Control ID's are included in list outputs")
	_ = listCmd.PersistentFlags().MarkHidden("id")
	_ = listCmd.PersistentFlags().MarkDeprecated("id", "Control ID's are included in list outputs")

	return listCmd
}

// Check if the flag entered are valid
func flagValidationList(listPolicies *v1.ListPolicies) error {

	// Validate the user's credentials
	return cautils.ValidateAccountID(listPolicies.AccountID)
}

func validateControlListFilters(target string, filters v1.ControlListFilters) error {
	if strings.TrimSpace(filters.Framework) == "" && strings.TrimSpace(filters.Search) == "" {
		return nil
	}
	if target != "controls" {
		return fmt.Errorf("--framework and --search can only be used with 'list controls'")
	}
	return nil
}
