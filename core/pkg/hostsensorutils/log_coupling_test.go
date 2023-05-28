package hostsensorutils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLogsMap_Update(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		logs        []string
		expectedLog string
		expected    int
	}{
		{
			name: "test_1",
			logs: []string{
				"log_1",
				"log_1",
				"log_1",
			},
			expectedLog: "log_1",
			expected:    3,
		},
		{
			name:        "test_2",
			logs:        []string{},
			expectedLog: "log_2",
			expected:    0,
		},
		{
			name: "test_3",
			logs: []string{
				"log_3",
			},
			expectedLog: "log_3",
			expected:    1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lm := NewLogCoupling()
			for _, log := range tt.logs {
				lm.update(log)
			}
			if !assert.Equal(t, lm.getOccurrence(tt.expectedLog), tt.expected) {
				t.Log("log occurrences are different")
			}
		})
	}
}

func TestLogsMap_IsDuplicated(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		logs        []string
		expectedLog string
		expected    bool
	}{
		{
			name: "test_1",
			logs: []string{
				"log_1",
				"log_1",
				"log_1",
			},
			expectedLog: "log_1",
			expected:    true,
		},
		{
			name: "test_2",
			logs: []string{
				"log_1",
				"log_1",
			},
			expectedLog: "log_2",
			expected:    false,
		},
		{
			name:        "test_3",
			logs:        []string{},
			expectedLog: "log_3",
			expected:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lm := NewLogCoupling()
			for _, log := range tt.logs {
				lm.update(log)
			}
			if !assert.Equal(t, lm.isDuplicated(tt.expectedLog), tt.expected) {
				t.Log("duplication value differ from expected")
			}
		})
	}
}
