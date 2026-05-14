package cautils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateAccountID(t *testing.T) {
	tests := []struct {
		name          string
		accountID     string
		expectedError string
	}{
		{
			name:      "valid account ID",
			accountID: "22019933-feac-4012-a8eb-e81461ba6655",
		},
		{
			name:      "empty account ID is allowed",
			accountID: "",
		},
		{
			name:          "too short account ID",
			accountID:     "22019933-feac-4012-a8eb-e81461ba665",
			expectedError: "bad argument: accound ID must be a valid UUID",
		},
		{
			name:          "non uuid account ID",
			accountID:     "not-a-uuid",
			expectedError: "bad argument: accound ID must be a valid UUID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAccountID(tt.accountID)

			if tt.expectedError != "" {
				assert.EqualError(t, err, tt.expectedError)
				return
			}

			assert.NoError(t, err)
		})
	}
}
