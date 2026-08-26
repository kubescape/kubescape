package config

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/kubescape/kubescape/v4/core/meta"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
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

var supportConfigSet = map[string]func(*metav1.SetConfig, string) error{
	"accessKey":      func(s *metav1.SetConfig, accessKey string) error { s.AccessKey = accessKey; return nil },
	"accountID":      func(s *metav1.SetConfig, account string) error { s.Account = account; return nil },
	"cloudAPIURL":    func(s *metav1.SetConfig, cloudAPIURL string) error { 
		if err := validateURL(cloudAPIURL); err != nil {
			return fmt.Errorf("invalid cloudAPIURL: %w", err)
		}
		s.CloudAPIURL = cloudAPIURL
		return nil
	},
	"cloudReportURL": func(s *metav1.SetConfig, cloudReportURL string) error { 
		if err := validateURL(cloudReportURL); err != nil {
			return fmt.Errorf("invalid cloudReportURL: %w", err)
		}
		s.CloudReportURL = cloudReportURL
		return nil
	},
}

func validateURL(u string) error {
	parsed, err := url.ParseRequestURI(u)
	if err != nil {
		return err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("URL scheme must be http or https")
	}
	return nil
}

func stringKeysToSlice(m map[string]func(*metav1.SetConfig, string) error) []string {
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

// normalizeConfigKey standardizes a key by stripping hyphens/underscores and converting to lowercase.
func normalizeConfigKey(key string) string {
	key = strings.ToLower(key)
	key = strings.ReplaceAll(key, "-", "")
	key = strings.ReplaceAll(key, "_", "")
	return key
}

func findConfigSetter(key string) (func(*metav1.SetConfig, string) error, bool) {
	if setter, ok := supportConfigSet[key]; ok {
		return setter, true
	}
	normalized := normalizeConfigKey(key)
	if normalized == "account" {
		normalized = "accountid"
	}
	for canonicalKey, setter := range supportConfigSet {
		if normalizeConfigKey(canonicalKey) == normalized {
			return setter, true
		}
	}
	return nil, false
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
		//nolint:gosec // len(args) is checked in switch
		value = args[1]
	default:
		return nil, fmt.Errorf("too many arguments: expected KEY=VALUE or KEY VALUE; supported keys: %s", supported)
	}

	setConfig := &metav1.SetConfig{}
	if setConfigFunc, ok := findConfigSetter(key); ok {
		if err := setConfigFunc(setConfig, value); err != nil {
			return nil, err
		}
		return setConfig, nil
	}
	return setConfig, fmt.Errorf("key %q unknown; supported: %s", key, supported)
}
