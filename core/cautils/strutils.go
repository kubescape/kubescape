package cautils

import (
	"fmt"
	"os"
	"sort"
	"strconv"
)

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
