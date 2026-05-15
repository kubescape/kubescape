package config

import (
	"fmt"
	"sort"
	"strings"

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
			return ks.SetCachedConfig(setConfig)
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
	supported := strings.Join(stringKeysToSlice(supportConfigSet), "/")

	var key, value string
	switch len(args) {
	case 0:
		return nil, fmt.Errorf("missing arguments: expected KEY=VALUE or KEY VALUE; supported keys: %s", supported)
	case 1:
		parts := strings.SplitN(args[0], "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid argument %q: expected KEY=VALUE or two arguments KEY VALUE; supported keys: %s", args[0], supported)
		}
		key = strings.TrimSpace(parts[0])
		if key == "" {
			return nil, fmt.Errorf("invalid argument %q: key cannot be empty", args[0])
		}
		value = parts[1]
	case 2:
		key = strings.TrimSpace(args[0])
		if key == "" {
			return nil, fmt.Errorf("invalid arguments: key cannot be empty")
		}
		value = args[1]
	default:
		return nil, fmt.Errorf("too many arguments: expected KEY=VALUE or KEY VALUE; supported keys: %s", supported)
	}

	setConfig := &metav1.SetConfig{}
	if setConfigFunc, ok := supportConfigSet[key]; ok {
		setConfigFunc(setConfig, value)
		return setConfig, nil
	}
	return setConfig, fmt.Errorf("key %q unknown; supported: %s", key, supported)
}
