package printer

import "testing"

func Test_scoreToSeverityLevel(t *testing.T) {
	tc := []struct {
		Name               string
		ScoreFactor        float32
		ExpectedSARIFLevel sarifSeverityLevel
	}{
		{"Score factor 1.0 should map to 'note' SARIF level", 1.0, sarifSeverityLevelNote},
		{"Score facore 4.0 should map to 'warning' SARIF level", 4.0, sarifSeverityLevelWarning},
		{"Score facore 7.0 should map to 'warning' SARIF level", 7.0, sarifSeverityLevelWarning},
		{"Score facore 9.0 should map to 'error' SARIF level", 9.0, sarifSeverityLevelError},
	}

	for _, testCase := range tc {
		t.Run(testCase.Name, func(t *testing.T) {
			got := scoreFactorToSARIFSeverityLevel(testCase.ScoreFactor)
			want := testCase.ExpectedSARIFLevel

			if got != want {
				t.Errorf("got %s, want %s", got, want)
			}
		})
	}
}
