package cautils

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// ConvertLabelsToString converts a map of labels to a semicolon-separated string
func ConvertLabelsToString(labels map[string]string) string {
	var builder strings.Builder
	delimiter := ""
	for k, v := range labels {
		builder.WriteString(fmt.Sprintf("%s%s=%s", delimiter, k, v))
		delimiter = ";"
	}
	return builder.String()
}

// ConvertStringToLabels converts a semicolon-separated string to a map of labels
func ConvertStringToLabels(labelsStr string) map[string]string {
	labels := make(map[string]string)
	labelsSlice := strings.Split(labelsStr, ";")
	for _, label := range labelsSlice {
		kvSlice := strings.SplitN(label, "=", 2)
		if len(kvSlice) != 2 {
			continue
		}
		labels[kvSlice[0]] = kvSlice[1]
	}
	return labels
}

func StringSlicesAreEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func ParseIntEnvVar(varName string, defaultValue int) (int, error) {
	varValue, exists := os.LookupEnv(varName)
	if !exists {
		return defaultValue, nil
	}

	intValue, err := strconv.Atoi(varValue)
	if err != nil {
		return defaultValue, fmt.Errorf("failed to parse %s env var as int: %w", varName, err)
	}

	return intValue, nil
}

func ParseBoolEnvVar(varName string, defaultValue bool) (bool, error) {
	varValue, exists := os.LookupEnv(varName)
	if !exists {
		return defaultValue, nil
	}

	boolValue, err := strconv.ParseBool(varValue)
	if err != nil {
		return defaultValue, fmt.Errorf("failed to parse %s env var as bool: %w", varName, err)
	}

	return boolValue, nil
}
