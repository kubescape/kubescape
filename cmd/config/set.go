package config

import (
	"fmt"
	"strings"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v2/core/meta"
	metav1 "github.com/kubescape/kubescape/v2/core/meta/datastructures/v1"
	"github.com/spf13/cobra"
)

func getSetCmd(ks meta.IKubescape) *cobra.Command {

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
			if err := ks.SetCachedConfig(setConfig); err != nil {
				logger.L().Fatal(err.Error())
			}
			return nil
		},
	}
	return configSetCmd
}

var supportConfigSet = map[string]func(*metav1.SetConfig, string){
	"accountID":      func(s *metav1.SetConfig, account string) { s.Account = account },
	"clientID":       func(s *metav1.SetConfig, clientID string) { s.ClientID = clientID },
	"secretKey":      func(s *metav1.SetConfig, secretKey string) { s.SecretKey = secretKey },
	"cloudAPIURL":    func(s *metav1.SetConfig, cloudAPIURL string) { s.CloudAPIURL = cloudAPIURL },
	"cloudAuthURL":   func(s *metav1.SetConfig, cloudAuthURL string) { s.CloudAuthURL = cloudAuthURL },
	"cloudReportURL": func(s *metav1.SetConfig, cloudReportURL string) { s.CloudReportURL = cloudReportURL },
	"cloudUIURL":     func(s *metav1.SetConfig, cloudUIURL string) { s.CloudUIURL = cloudUIURL },
}

func stringKeysToSlice(m map[string]func(*metav1.SetConfig, string)) []string {
	l := []string{}
	for i := range m {
		l = append(l, i)
	}
	return l
}

func parseSetArgs(args []string) (*metav1.SetConfig, error) {
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
	setConfig := &metav1.SetConfig{}

	if setConfigFunc, ok := supportConfigSet[key]; ok {
		setConfigFunc(setConfig, value)
	} else {
		return setConfig, fmt.Errorf("key '%s' unknown . supported: %s", key, strings.Join(stringKeysToSlice(supportConfigSet), "/"))
	}
	return setConfig, nil
}
