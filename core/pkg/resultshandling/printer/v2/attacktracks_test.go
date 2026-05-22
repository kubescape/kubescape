package printer

import (
	"testing"

	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
	"github.com/stretchr/testify/assert"
)

func TestPrettyPrinterCreateFailedControlList(t *testing.T) {
	tests := []struct {
		name     string
		controls []v1alpha1.IAttackTrackControl
		expected string
	}{
		{
			name:     "no controls",
			controls: nil,
			expected: "",
		},
		{
			name: "single control",
			controls: []v1alpha1.IAttackTrackControl{
				&v1alpha1.AttackTrackControlMock{ControlId: "C-001"},
			},
			expected: "C-001",
		},
		{
			name: "multiple controls preserve order",
			controls: []v1alpha1.IAttackTrackControl{
				&v1alpha1.AttackTrackControlMock{ControlId: "C-001"},
				&v1alpha1.AttackTrackControlMock{ControlId: "C-002"},
				&v1alpha1.AttackTrackControlMock{ControlId: "C-003"},
			},
			expected: "C-001, C-002, C-003",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pp := &PrettyPrinter{}
			step := v1alpha1.AttackTrackStepMock{
				Name:     "attack step",
				Controls: tt.controls,
			}

			assert.Equal(t, tt.expected, pp.createFailedControlList(step))
		})
	}
}
