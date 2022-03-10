package config

import (
	"fmt"
	"strings"

	"github.com/armosec/kubescape/cautils/logger"
	"github.com/armosec/kubescape/clihandler"
	"github.com/armosec/kubescape/clihandler/cliobjects"
	"github.com/spf13/cobra"
)

func getSetCmd() *cobra.Command {

	// configCmd represents the config command
	configSetCmd := &cobra.Command{
		Use:       "set",
		Short:     fmt.Sprintf("Set configurations, supported: %s", strings.Join(stringKeysToSlice(supportConfigSet), "/")),
		Example:   setConfigExample,
		ValidArgs: stringKeysToSlice(supportConfigSet),
		RunE: func(cmd *cobra.Command, args []string) error {
			setConfig, err := parseSetArgs(args)
			if err != nil {
				return err
			}
			if err := clihandler.CliSetConfig(setConfig); err != nil {
				logger.L().Fatal(err.Error())
			}
			return nil
		},
	}
	return configSetCmd
}

var supportConfigSet = map[string]func(*cliobjects.SetConfig, string){
	"accountID": func(s *cliobjects.SetConfig, account string) { s.Account = account },
	"clientID":  func(s *cliobjects.SetConfig, clientID string) { s.ClientID = clientID },
	"secretKey": func(s *cliobjects.SetConfig, secretKey string) { s.SecretKey = secretKey },
}

func stringKeysToSlice(m map[string]func(*cliobjects.SetConfig, string)) []string {
	l := []string{}
	for i := range m {
		l = append(l, i)
	}
	return l
}

func parseSetArgs(args []string) (*cliobjects.SetConfig, error) {
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
	setConfig := &cliobjects.SetConfig{}

	if setConfigFunc, ok := supportConfigSet[key]; ok {
		setConfigFunc(setConfig, value)
	} else {
		return setConfig, fmt.Errorf("key '%s' unknown . supported: %s", key, strings.Join(stringKeysToSlice(supportConfigSet), "/"))
	}
	return setConfig, nil
}
