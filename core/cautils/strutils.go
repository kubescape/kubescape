package cautils

import (
	"fmt"
	"os"
	"slices"
	"strconv"
	"time"
)

// StringSlicesAreEqual reports whether a and b contain the same elements,
// ignoring order. It sorts copies rather than the arguments: callers pass
// slices they do not exclusively own (e.g. the policy handler's cached
// identifiers), and sorting those in place would mutate shared state outside
// the owner's lock.
func StringSlicesAreEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	return slices.Equal(slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b)))
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

// ParseDurationEnvVar reads varName and parses it with time.ParseDuration,
// accepting Go duration strings such as "90s", "5m" or "1h30m". It returns
// defaultValue when the variable is unset, and defaultValue plus an error
// when it is set but unparsable. A bare number without a unit (e.g. "5") is
// an error. Negative durations are accepted; call sites own that validation.
func ParseDurationEnvVar(varName string, defaultValue time.Duration) (time.Duration, error) {
	varValue, exists := os.LookupEnv(varName)
	if !exists {
		return defaultValue, nil
	}

	d, err := time.ParseDuration(varValue)
	if err != nil {
		return defaultValue, fmt.Errorf("failed to parse %s env var as duration: %w", varName, err)
	}

	return d, nil
}
