package cautils

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type ConfigOutputField struct {
	Name  string
	Value string
}

// FormatConfigOutput renders configuration data in the requested output format.
// Supported values: json, yaml, text. The default format is text.
func FormatConfigOutput(cfg *ConfigObj, format string, includeEmpty bool) ([]byte, error) {
	if cfg == nil {
		cfg = &ConfigObj{}
	}

	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = "text"
	}

	switch format {
	case "json":
		return formatConfigOutputJSON(cfg, includeEmpty)
	case "yaml":
		return formatConfigOutputYAML(cfg, includeEmpty)
	case "text":
		return formatConfigOutputText(cfg, includeEmpty)
	default:
		return nil, fmt.Errorf("unsupported output format %q", format)
	}
}

func formatConfigOutputJSON(cfg *ConfigObj, includeEmpty bool) ([]byte, error) {
	payload := map[string]string{}
	for _, field := range ConfigOutputFields(cfg) {
		if includeEmpty || field.Value != "" {
			payload[field.Name] = field.Value
		}
	}
	return json.MarshalIndent(payload, "", "  ")
}

func formatConfigOutputYAML(cfg *ConfigObj, includeEmpty bool) ([]byte, error) {
	payload := map[string]string{}
	for _, field := range ConfigOutputFields(cfg) {
		if includeEmpty || field.Value != "" {
			payload[field.Name] = field.Value
		}
	}
	return yaml.Marshal(payload)
}

func formatConfigOutputText(cfg *ConfigObj, includeEmpty bool) ([]byte, error) {
	var lines []string
	for _, field := range ConfigOutputFields(cfg) {
		if includeEmpty || field.Value != "" {
			lines = append(lines, fmt.Sprintf("%s: %s", field.Name, field.Value))
		}
	}
	return []byte(strings.Join(lines, "\n") + "\n"), nil
}

func ConfigOutputFields(cfg *ConfigObj) []ConfigOutputField {
	return []ConfigOutputField{
		{Name: "accountID", Value: cfg.AccountID},
		{Name: "clusterName", Value: cfg.ClusterName},
		{Name: "cloudReportURL", Value: cfg.CloudReportURL},
		{Name: "cloudAPIURL", Value: cfg.CloudAPIURL},
		{Name: "accessKey", Value: maskAccessKey(cfg.AccessKey)},
	}
}

// FormatConfigFieldOutput renders a single configuration field.
func FormatConfigFieldOutput(field ConfigOutputField, format string) ([]byte, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = "text"
	}

	switch format {
	case "json":
		return json.MarshalIndent(map[string]string{field.Name: field.Value}, "", "  ")
	case "yaml":
		return yaml.Marshal(map[string]string{field.Name: field.Value})
	case "text":
		return []byte(field.Value + "\n"), nil
	default:
		return nil, fmt.Errorf("unsupported output format %q", format)
	}
}

// accessKeyMask replaces the secret part of the access key when it is rendered.
const accessKeyMask = "****"

// maskAccessKey hides the cached access key. The key is a Kubescape Cloud
// credential - it is persisted with 0600 permissions and elsewhere only ever
// logged by length - while this output is written straight to stdout,
// including in the CI logs and shared terminals the command is documented
// for. Only the last four characters are kept, so an operator can still tell
// which key is cached, and the mask has a fixed width so the length of the key
// is not disclosed either.
// The key itself remains readable in the config file for anyone who needs it.
func maskAccessKey(accessKey string) string {
	if accessKey == "" {
		return ""
	}
	// Keeping the tail of a short key would give away most of it, so such a
	// key is masked in full.
	key := []rune(accessKey)
	if len(key) <= 8 {
		return accessKeyMask
	}
	return accessKeyMask + string(key[len(key)-4:])
}
