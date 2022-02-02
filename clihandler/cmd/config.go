package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/armosec/kubescape/clihandler"
	"github.com/armosec/kubescape/clihandler/cliobjects"
	"github.com/spf13/cobra"
)

var (
	configExample = `
  # View cached configurations 
  kubescape config view

  # Delete cached configurations
  kubescape config delete

  # Set cached configurations
  kubescape config set --help
`
	setConfigExample = `
  # Set account id
  kubescape config set accountID <account id>

  # Set client id
  kubescape config set clientID <client id> 

  # Set access key
  kubescape config set accessKey <access key>
`
)

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:     "config",
	Short:   "handle cached configurations",
	Example: configExample,
}

var setConfig = cliobjects.SetConfig{}

// configCmd represents the config command
var configSetCmd = &cobra.Command{
	Use:       "set",
	Short:     fmt.Sprintf("Set configurations, supported: %s", strings.Join(stringKeysToSlice(supportConfigSet), "/")),
	Example:   setConfigExample,
	ValidArgs: stringKeysToSlice(supportConfigSet),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := parseSetArgs(args); err != nil {
			return err
		}
		if err := clihandler.CliSetConfig(&setConfig); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return nil
	},
}

var supportConfigSet = map[string]func(*cliobjects.SetConfig, string){
	"accountID": func(s *cliobjects.SetConfig, account string) { s.Account = account },
	"clientID":  func(s *cliobjects.SetConfig, clientID string) { s.ClientID = clientID },
	"accessKey": func(s *cliobjects.SetConfig, accessKey string) { s.AccessKey = accessKey },
}

func stringKeysToSlice(m map[string]func(*cliobjects.SetConfig, string)) []string {
	l := []string{}
	for i := range m {
		l = append(l, i)
	}
	return l
}

func parseSetArgs(args []string) error {
	var key string
	var value string
	if len(args) == 1 {
		if keyValue := strings.Split(args[0], "="); len(keyValue) == 2 {
			key = keyValue[0]
			value = keyValue[1]
		}
	} else if len(args) == 2 {
		key = args[0]
		value = args[1]
	}
	if setConfigFunc, ok := supportConfigSet[key]; ok {
		setConfigFunc(&setConfig, value)
	} else {
		return fmt.Errorf("key '%s' unknown . supported: %s", key, strings.Join(stringKeysToSlice(supportConfigSet), "/"))
	}
	return nil
}

var configDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete cached configurations",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if err := clihandler.CliDelete(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	},
}

// configCmd represents the config command
var configViewCmd = &cobra.Command{
	Use:   "view",
	Short: "View cached configurations",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		if err := clihandler.CliView(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configDeleteCmd)
	configCmd.AddCommand(configViewCmd)
}
