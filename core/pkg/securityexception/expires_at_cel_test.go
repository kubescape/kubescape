package securityexception

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// expiresAtRuleValid mirrors the CEL validation rule for the expiresAt field:
//
//	!has(self.spec.expiresAt)
//	  || (has(oldSelf.spec.expiresAt) && oldSelf.spec.expiresAt == self.spec.expiresAt)
//	  || timestamp(self.spec.expiresAt) > now()
//
// Parameters:
//
//	expiresAt  – the new value of spec.expiresAt; nil means the field is absent.
//	oldExpires – the previous value of spec.expiresAt; nil means absent or this is a create.
//	now        – the current timestamp used for comparison.
func expiresAtRuleValid(expiresAt *time.Time, oldExpires *time.Time, now time.Time) bool {
	// Field absent → always valid.
	if expiresAt == nil {
		return true
	}
	// Field present but unchanged from previous version → always valid.
	if oldExpires != nil && oldExpires.Equal(*expiresAt) {
		return true
	}
	// Field newly set or changed → must be in the future.
	return expiresAt.After(now)
}

func TestExpiresAtCELRule(t *testing.T) {
	now := time.Now()
	future := now.Add(24 * time.Hour)
	past := now.Add(-24 * time.Hour)

	tests := []struct {
		name       string
		expiresAt  *time.Time
		oldExpires *time.Time
		want       bool
	}{
		{
			name:       "create with future expiresAt is admitted",
			expiresAt:  &future,
			oldExpires: nil,
			want:       true,
		},
		{
			name:       "create with past expiresAt is rejected",
			expiresAt:  &past,
			oldExpires: nil,
			want:       false,
		},
		{
			name:       "create without expiresAt is admitted",
			expiresAt:  nil,
			oldExpires: nil,
			want:       true,
		},
		{
			name:       "update with unchanged past expiresAt is admitted",
			expiresAt:  &past,
			oldExpires: &past,
			want:       true,
		},
		{
			name:       "update changing to a new past expiresAt is rejected",
			expiresAt:  &past,
			oldExpires: &future,
			want:       false,
		},
		{
			name:       "update changing to a new future expiresAt is admitted",
			expiresAt:  &future,
			oldExpires: &past,
			want:       true,
		},
		{
			name:       "update removing expiresAt is admitted",
			expiresAt:  nil,
			oldExpires: &past,
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := expiresAtRuleValid(tt.expiresAt, tt.oldExpires, now)
			assert.Equal(t, tt.want, got)
		})
	}
}
