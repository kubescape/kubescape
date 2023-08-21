package cautils

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

func ConvertLabelsToString(labels map[string]string) string {
	labelsStr := ""
	delimiter := ""
	for k, v := range labels {
		labelsStr += fmt.Sprintf("%s%s=%s", delimiter, k, v)
		delimiter = ";"
	}
	return labelsStr
}

// ConvertStringToLabels convert a string "a=b;c=d" to map: {"a":"b", "c":"d"}
func ConvertStringToLabels(labelsStr string) map[string]string {
	labels := make(map[string]string)
	labelsSlice := strings.Split(labelsStr, ";")
	if len(labelsSlice)%2 != 0 {
		return labels
	}
	for i := range labelsSlice {
		kvSlice := strings.Split(labelsSlice[i], "=")
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
