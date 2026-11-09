package networkpolicy

import (
	"math"
	"strconv"
	"testing"
)

func TestSafePortInt32Bounds(t *testing.T) {
	type testCase struct {
		name string
		port int
		want int32
		ok   bool
	}
	tests := []testCase{
		{name: "minimum int32", port: math.MinInt32, want: math.MinInt32, ok: true},
		{name: "maximum int32", port: math.MaxInt32, want: math.MaxInt32, ok: true},
	}

	if strconv.IntSize > 32 {
		aboveMax := int64(math.MaxInt32) + 1
		belowMin := int64(math.MinInt32) - 1
		tests = append(tests,
			testCase{name: "above maximum int32", port: int(aboveMax), ok: false},
			testCase{name: "below minimum int32", port: int(belowMin), ok: false},
		)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := safePort(tt.port)
			if got != tt.want || ok != tt.ok {
				t.Errorf("safePort(%d) = (%d, %t), want (%d, %t)", tt.port, got, ok, tt.want, tt.ok)
			}
		})
	}
}
