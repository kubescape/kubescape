package cautils

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConvertLabelsToString(t *testing.T) {
	str := "a=b;c=d"
	strMap := map[string]string{"a": "b", "c": "d"}
	rsrt := ConvertLabelsToString(strMap)
	spilltedA := strings.Split(rsrt, ";")
	spilltedB := strings.Split(str, ";")
	for i := range spilltedA {
		exists := false
		for j := range spilltedB {
			if spilltedB[j] == spilltedA[i] {
				exists = true
			}
		}
		if !exists {
			t.Errorf("%s != %s", spilltedA[i], spilltedB[i])
		}
	}
}

func TestConvertLabelsToString_EdgeCases(t *testing.T) {
	// Test case 1: Empty map
	emptyMap := make(map[string]string)
	result := ConvertLabelsToString(emptyMap)
	expected := ""
	if result != expected {
		t.Errorf("Empty map test failed, expected: '%s', got: '%s'", expected, result)
	}

	// Test case 2: Single pair in map
	singlePairMap := map[string]string{"key": "value"}
	result = ConvertLabelsToString(singlePairMap)
	expected = "key=value"
	if result != expected {
		t.Errorf("Single pair test failed, expected: '%s', got: '%s'", expected, result)
	}

	// Test case 3: Multiple pairs in map
	multiplePairsMap := map[string]string{"key1": "value1", "key2": "value2", "key3": "value3"}
	result = ConvertLabelsToString(multiplePairsMap)
	expected = "key1=value1;key2=value2;key3=value3"
	if result != expected {
		t.Errorf("Multiple pairs test failed, expected: '%s', got: '%s'", expected, result)
	}

	// Test case 4: Special characters in keys or values
	specialCharsMap := map[string]string{"key with spaces": "value with symbols (!@#)", "key\nwith\nnewlines": "value\rwith\rreturns"}
	result = ConvertLabelsToString(specialCharsMap)
	expected = "key with spaces=value with symbols (!@#);key\nwith\nnewlines=value\rwith\rreturns"
	if result != expected {
		t.Errorf("Special characters test failed, expected: '%s', got: '%s'", expected, result)
	}

	// Test case 5: Reserved characters in keys or values
	reservedCharsMap := map[string]string{"key=with=equal=sign": "value;with;semicolon", "key;with;semicolon": "value=with=equal=sign"}
	result = ConvertLabelsToString(reservedCharsMap)
	expected = "key=with=equal=sign=value;with;semicolon;key;with;semicolon=value=with=equal=sign"
	if result != expected {
		t.Errorf("Reserved characters test failed, expected: '%s', got: '%s'", expected, result)
	}
}

func TestConvertStringToLabels(t *testing.T) {
	str := "a=b;c=d"
	strMap := map[string]string{"a": "b", "c": "d"}
	rstrMap := ConvertStringToLabels(str)
	if fmt.Sprintf("%v", rstrMap) != fmt.Sprintf("%v", strMap) {
		t.Errorf("%s != %s", fmt.Sprintf("%v", rstrMap), fmt.Sprintf("%v", strMap))
	}
}

func TestConvertStringToLabels_EdgeCases(t *testing.T) {
	// Test case 1: Empty string
	result := ConvertStringToLabels("")
	expected := map[string]string{}
	if fmt.Sprintf("%v", result) != fmt.Sprintf("%v", expected) {
		t.Errorf("Empty string test failed, expected: %v, got: %v", expected, result)
	}

	// Test case 2: Single pair in string
	result = ConvertStringToLabels("key=value")
	expected = map[string]string{"key": "value"}
	if fmt.Sprintf("%v", result) != fmt.Sprintf("%v", expected) {
		t.Errorf("Single pair test failed, expected: %v, got: %v", expected, result)
	}

	// Test case 3: Multiple pairs in string
	result = ConvertStringToLabels("key1=value1;key2=value2;key3=value3")
	expected = map[string]string{"key1": "value1", "key2": "value2", "key3": "value3"}
	if fmt.Sprintf("%v", result) != fmt.Sprintf("%v", expected) {
		t.Errorf("Multiple pairs test failed, expected: %v, got: %v", expected, result)
	}

	// Test case 4: Special characters in string
	result = ConvertStringToLabels("key with spaces=value with symbols (!@#);key\nwith\nnewlines=value\rwith\rreturns")
	expected = map[string]string{"key with spaces": "value with symbols (!@#)", "key\nwith\nnewlines": "value\rwith\rreturns"}
	if fmt.Sprintf("%v", result) != fmt.Sprintf("%v", expected) {
		t.Errorf("Special characters test failed, expected: %v, got: %v", expected, result)
	}

	// Test case 5: Malformed string
	result = ConvertStringToLabels("key=value;key2")
	expected = map[string]string{"key": "value"}
	if fmt.Sprintf("%v", result) != fmt.Sprintf("%v", expected) {
		t.Errorf("Malformed string test failed, expected: %v, got: %v", expected, result)
	}

	result = ConvertStringToLabels("k=y=val;u=e")
	expected = map[string]string{"k": "y=val", "u": "e"}
	if fmt.Sprintf("%v", result) != fmt.Sprintf("%v", expected) {
		t.Errorf("Special characters test failed, expected: %v, got: %v", expected, result)
	}
}

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
