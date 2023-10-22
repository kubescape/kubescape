package config

import (
	"fmt"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/meta"
	"github.com/spf13/cobra"
)

var (
	configExample = fmt.Sprintf(`
  # View cached configurations 
  %[1]s config view

  # Delete cached configurations
  %[1]s config delete

  # Set cached configurations
  %[1]s config set --help
`, cautils.ExecName())
	setConfigExample = fmt.Sprintf(`
  # Set account id
  %[1]s config set accountID <account id>

  # Set cloud report URL
  %[1]s config set cloudReportURL <cloud Report URL>
`, cautils.ExecName())
)

func GetConfigCmd(ks meta.IKubescape) *cobra.Command {

	// configCmd represents the config command
	configCmd := &cobra.Command{
		Use:     "config",
		Short:   "Handle cached configurations",
		Example: configExample,
	}

	configCmd.AddCommand(getDeleteCmd(ks))
	configCmd.AddCommand(getSetCmd(ks))
	configCmd.AddCommand(getViewCmd(ks))

	return configCmd
}
