package prettyprinter

import (
	"testing"

	"github.com/kubescape/opa-utils/reporthandling"
)

func TestRepoScan_getNextSteps(t *testing.T) {
	repoPrinter := &RepoPrinter{}

	nextSteps := repoPrinter.getNextSteps()

	if len(nextSteps) != 4 {
		t.Errorf("Expected 4 next steps, got %d", len(nextSteps))
	}

	if nextSteps[0] != runCommandsText {
		t.Errorf("Expected %s, got %s", clusterScanRunText, nextSteps[0])
	}

	if nextSteps[1] != clusterScanRunText {
		t.Errorf("Expected %s, got %s", runCommandsText, nextSteps[1])
	}

	if nextSteps[2] != scanWorkloadText {
		t.Errorf("Expected %s, got %s", scanWorkloadText, nextSteps[2])
	}

	if nextSteps[3] != installKubescapeText {
		t.Errorf("Expected %s, got %s", installKubescapeText, nextSteps[3])
	}
}

func TestRepoScan_getWorkloadScanCommand(t *testing.T) {
	test := []struct {
		testName string
		ns       string
		kind     string
		name     string
		source   reporthandling.Source
		want     string
	}{
		{
			testName: "file path",
			ns:       "ns",
			kind:     "kind",
			name:     "name",
			source: reporthandling.Source{
				Path:         "path",
				RelativePath: "relativePath",
			},
			want: "$ kubescape scan workload kind/name --namespace ns --file-path=path/relativePath",
		},
		{
			testName: "helm path",
			ns:       "ns",
			kind:     "kind",
			name:     "name",
			source: reporthandling.Source{
				Path:         "path",
				RelativePath: "relativePath",
				HelmPath:     "helmPath",
				FileType:     "Helm Chart",
			},
			want: "$ kubescape scan workload kind/name --namespace ns --chart-path=helmPath --file-path=path/relativePath",
		},
		{
			testName: "file path - no namespace",
			kind:     "kind",
			name:     "name",
			source: reporthandling.Source{
				Path:         "path",
				RelativePath: "relativePath",
			},
			want: "$ kubescape scan workload kind/name --file-path=path/relativePath",
		},
		{
			testName: "helm path - no namespace",
			kind:     "kind",
			name:     "name",
			source: reporthandling.Source{
				Path:         "path",
				RelativePath: "relativePath",
				HelmPath:     "helmPath",
				FileType:     "Helm Chart",
			},
			want: "$ kubescape scan workload kind/name --chart-path=helmPath --file-path=path/relativePath",
		},
	}

	for _, tt := range test {
		t.Run(tt.testName, func(t *testing.T) {
			repoPrinter := &RepoPrinter{}

			if got := repoPrinter.getWorkloadScanCommand(tt.ns, tt.kind, tt.name, tt.source); got != tt.want {
				t.Errorf("in test %s failed, got = %v, want %v", tt.testName, got, tt.want)
			}
		})
	}

}
