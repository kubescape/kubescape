package cautils

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseIntEnvVar(t *testing.T) {
	testCases := []struct {
		expectedErr  string
		name         string
		varName      string
		varValue     string
		defaultValue int
		expected     int
	}{
		{
			name:         "Variable does not exist",
			varName:      "DOES_NOT_EXIST",
			varValue:     "",
			defaultValue: 123,
			expected:     123,
			expectedErr:  "",
		},
		{
			name:         "Variable exists and is a valid integer",
			varName:      "MY_VAR",
			varValue:     "456",
			defaultValue: 123,
			expected:     456,
			expectedErr:  "",
		},
		{
			name:         "Variable exists but is not a valid integer",
			varName:      "MY_VAR",
			varValue:     "not_an_integer",
			defaultValue: 123,
			expected:     123,
			expectedErr:  "failed to parse MY_VAR env var as int",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.varValue != "" {
				t.Setenv(tc.varName, tc.varValue)
			}

			actual, err := ParseIntEnvVar(tc.varName, tc.defaultValue)
			if tc.expectedErr != "" {
				assert.NotNil(t, err)
				assert.ErrorContains(t, err, tc.expectedErr)
			} else {
				assert.Nil(t, err)
			}

			assert.Equalf(t, tc.expected, actual, "unexpected result")
		})
	}
}

func TestStringSlicesAreEqual(t *testing.T) {
	tt := []struct {
		name string
		a    []string
		b    []string
		want bool
	}{
		{
			name: "equal unsorted slices",
			a:    []string{"foo", "bar", "baz"},
			b:    []string{"baz", "foo", "bar"},
			want: true,
		},
		{
			name: "equal sorted slices",
			a:    []string{"bar", "baz", "foo"},
			b:    []string{"bar", "baz", "foo"},
			want: true,
		},
		{
			name: "unequal slices",
			a:    []string{"foo", "bar", "baz"},
			b:    []string{"foo", "bar", "qux"},
			want: false,
		},
		{
			name: "different length slices",
			a:    []string{"foo", "bar", "baz"},
			b:    []string{"foo", "bar"},
			want: false,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			got := StringSlicesAreEqual(tc.a, tc.b)
			if got != tc.want {
				t.Errorf("StringSlicesAreEqual(%v, %v) = %v; want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestStringSlicesAreEqual_NoMutation(t *testing.T) {
	a := []string{"foo", "bar", "baz"}
	b := []string{"baz", "foo", "bar"}

	assert.True(t, StringSlicesAreEqual(a, b), "slices with the same elements must compare equal")

	assert.Equal(t, []string{"foo", "bar", "baz"}, a, "StringSlicesAreEqual must not mutate a")
	assert.Equal(t, []string{"baz", "foo", "bar"}, b, "StringSlicesAreEqual must not mutate b")
}

func TestParseBoolEnvVar(t *testing.T) {
	testCases := []struct {
		expectedErr  string
		name         string
		varName      string
		varValue     string
		defaultValue bool
		expected     bool
	}{
		{
			name:         "Variable does not exist",
			varName:      "DOES_NOT_EXIST",
			varValue:     "",
			defaultValue: true,
			expected:     true,
			expectedErr:  "",
		},
		{
			name:         "Variable exists and is a valid bool",
			varName:      "MY_VAR",
			varValue:     "true",
			defaultValue: false,
			expected:     true,
			expectedErr:  "",
		},
		{
			name:         "Variable exists but is not a valid bool",
			varName:      "MY_VAR",
			varValue:     "not_a_boolean",
			defaultValue: false,
			expected:     false,
			expectedErr:  "failed to parse MY_VAR env var as bool",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.varValue != "" {
				t.Setenv(tc.varName, tc.varValue)
			}

			actual, err := ParseBoolEnvVar(tc.varName, tc.defaultValue)
			if tc.expectedErr != "" {
				assert.NotNil(t, err)
				assert.ErrorContains(t, err, tc.expectedErr)
			} else {
				assert.Nil(t, err)
			}

			assert.Equalf(t, tc.expected, actual, "unexpected result")
		})
	}
}

func TestParseDurationEnvVar(t *testing.T) {
	testCases := []struct {
		expectedErr  string
		name         string
		varName      string
		varValue     string
		setEnv       bool
		defaultValue time.Duration
		expected     time.Duration
	}{
		{
			name:         "Variable does not exist",
			varName:      "DOES_NOT_EXIST",
			setEnv:       false,
			varValue:     "",
			defaultValue: 5 * time.Minute,
			expected:     5 * time.Minute,
			expectedErr:  "",
		},
		{
			name:         "Variable is exported but empty",
			varName:      "MY_VAR",
			setEnv:       true,
			varValue:     "",
			defaultValue: 5 * time.Minute,
			expected:     5 * time.Minute,
			expectedErr:  "failed to parse MY_VAR env var as duration",
		},
		{
			name:         "Variable exists and is a valid duration",
			varName:      "MY_VAR",
			setEnv:       true,
			varValue:     "90s",
			defaultValue: 5 * time.Minute,
			expected:     90 * time.Second,
			expectedErr:  "",
		},
		{
			name:         "Variable exists with compound duration",
			varName:      "MY_VAR",
			setEnv:       true,
			varValue:     "1h30m",
			defaultValue: 5 * time.Minute,
			expected:     90 * time.Minute,
			expectedErr:  "",
		},
		{
			name:         "Variable exists but is not a valid duration",
			varName:      "MY_VAR",
			setEnv:       true,
			varValue:     "not_a_duration",
			defaultValue: 5 * time.Minute,
			expected:     5 * time.Minute,
			expectedErr:  "failed to parse MY_VAR env var as duration",
		},
		{
			name:         "Variable exists with zero value",
			varName:      "MY_VAR",
			setEnv:       true,
			varValue:     "0s",
			defaultValue: 5 * time.Minute,
			expected:     0,
			expectedErr:  "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setEnv {
				t.Setenv(tc.varName, tc.varValue)
			} else {
				t.Setenv(tc.varName, "")
				os.Unsetenv(tc.varName)
			}

			actual, err := ParseDurationEnvVar(tc.varName, tc.defaultValue)
			if tc.expectedErr != "" {
				assert.NotNil(t, err)
				assert.ErrorContains(t, err, tc.expectedErr)
			} else {
				assert.Nil(t, err)
			}

			assert.Equalf(t, tc.expected, actual, "unexpected result")
		})
	}
}
