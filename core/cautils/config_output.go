package cautils

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type configOutputField struct {
	name  string
	value string
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
	for _, field := range configOutputFields(cfg) {
		if includeEmpty || field.value != "" {
			payload[field.name] = field.value
		}
	}
	return json.MarshalIndent(payload, "", "  ")
}

func formatConfigOutputYAML(cfg *ConfigObj, includeEmpty bool) ([]byte, error) {
	payload := map[string]string{}
	for _, field := range configOutputFields(cfg) {
		if includeEmpty || field.value != "" {
			payload[field.name] = field.value
		}
	}
	return yaml.Marshal(payload)
}

func formatConfigOutputText(cfg *ConfigObj, includeEmpty bool) ([]byte, error) {
	var lines []string
	for _, field := range configOutputFields(cfg) {
		if includeEmpty || field.value != "" {
			lines = append(lines, fmt.Sprintf("%s: %s", field.name, field.value))
		}
	}
	return []byte(strings.Join(lines, "\n") + "\n"), nil
}

func configOutputFields(cfg *ConfigObj) []configOutputField {
	return []configOutputField{
		{name: "accountID", value: cfg.AccountID},
		{name: "clusterName", value: cfg.ClusterName},
		{name: "cloudReportURL", value: cfg.CloudReportURL},
		{name: "cloudAPIURL", value: cfg.CloudAPIURL},
		{name: "accessKey", value: maskAccessKey(cfg.AccessKey)},
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
