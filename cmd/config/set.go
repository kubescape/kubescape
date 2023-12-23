package config

import (
	"fmt"
	"sort"
	"strings"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v3/core/meta"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
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
	"accessKey":      func(s *metav1.SetConfig, accessKey string) { s.AccessKey = accessKey },
	"accountID":      func(s *metav1.SetConfig, account string) { s.Account = account },
	"cloudAPIURL":    func(s *metav1.SetConfig, cloudAPIURL string) { s.CloudAPIURL = cloudAPIURL },
	"cloudReportURL": func(s *metav1.SetConfig, cloudReportURL string) { s.CloudReportURL = cloudReportURL },
}

func stringKeysToSlice(m map[string]func(*metav1.SetConfig, string)) []string {
	keys := []string{}
	for key := range m {
		keys = append(keys, key)
	}

	// Sort the keys of the map
	sort.Strings(keys)

	l := []string{}
	l = append(l, keys...)
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
