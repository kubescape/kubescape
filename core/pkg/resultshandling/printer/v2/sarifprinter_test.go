package printer

import (
	"testing"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/sergi/go-diff/diffmatchpatch"
)

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

func Test_collectDiffs(t *testing.T) {
	tc := []struct {
		Name        string
		fileString  string
		fixedString string
		fixesNum    int
		region      [][4]int
		text        []string
	}{
		{
			"Collect Diffs should work for add, delete and equal",

			`apiVersion: v1
kind: Pod
metadata:
  name: test

spec:
  containers:
  - name: nginx_container
    image: nginx
    securityContext:
      capabilities:
        drop: [NET_RAW]
      runAsRoot: true`,

			`apiVersion: v1
kind: Pod
metadata:
  name: test

spec:
  containers:
  - name: nginx_container
    image: nginx
    securityContext:
      capabilities:
        drop: [NET_RAW, SYS_ADM]
      runAsRoot: false
      allowPrivilegeEscalation: false`,
			3,
			[][4]int{
				{12, 23, 12, 23},
				{13, 18, 13, 19},
				{13, 20, 13, 21},
			},
			[]string{
				", SYS_ADM",
				`false
      allowP`,
				"ivilegeEscalation: fals",
			},
		},
	}

	for _, testCase := range tc {
		t.Run(testCase.Name, func(t *testing.T) {
			dmp := diffmatchpatch.New()
			diffs := dmp.DiffMain(testCase.fileString, testCase.fixedString, false)
			run := sarif.NewRunWithInformationURI(toolName, toolInfoURI)
			result := run.CreateResultForRule("0")
			collectDiffs(dmp, diffs, result, "", testCase.fileString)
			if len(result.Fixes) != testCase.fixesNum {
				t.Errorf("wrong Number of fixes, got %d, want %d", len(result.Fixes), testCase.fixesNum)
			}
			for index, fix := range result.Fixes {
				if len(fix.ArtifactChanges) != 1 {
					t.Errorf("wrong Number of artifactChanges in fix %d, got %d, want %d", index, len(fix.ArtifactChanges), 1)
				}
				replacements := fix.ArtifactChanges[0].Replacements
				if len(replacements) != 1 {
					t.Errorf("wrong Number of replacements in fix %d, got %d, want %d", index, len(replacements), 1)
				}
				startLine := *replacements[0].DeletedRegion.StartLine
				startColumn := *replacements[0].DeletedRegion.StartColumn
				endLine := *replacements[0].DeletedRegion.EndLine
				endColumn := *replacements[0].DeletedRegion.EndColumn
				location := testCase.region[index]
				if location[0] != startLine || location[1] != startColumn || location[2] != endLine || location[3] != endColumn {
					t.Errorf("wrong delete region in fix %d, got (%d, %d, %d, %d) want (%d, %d, %d, %d)",
						index, startLine, startColumn, endLine, endColumn, location[0], location[1], location[2], location[3])
				}
				if testCase.text[index] != *replacements[0].InsertedContent.Text {
					t.Errorf("wrong add text in fix %d, got (%s) want (%s)",
						index, *replacements[0].InsertedContent.Text, testCase.text[index])
				}
			}
		})
	}
}
