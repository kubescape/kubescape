package cautils

import (
	"fmt"
	"strings"
)

const ValueNotFound = -1

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

func StringInSlice(strSlice []string, str string) int {
	for i := range strSlice {
		if strSlice[i] == str {
			return i
		}
	}
	return ValueNotFound
}
