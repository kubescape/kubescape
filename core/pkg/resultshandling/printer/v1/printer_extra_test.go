package printer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJsonPrinterSetWriter(t *testing.T) {
	tests := []struct {
		name       string
		outputFile string
		wantSuffix string
	}{
		{
			name:       "adds json extension",
			outputFile: filepath.Join(t.TempDir(), "scan-result"),
			wantSuffix: "scan-result.json",
		},
		{
			name:       "keeps json extension",
			outputFile: filepath.Join(t.TempDir(), "scan-result.json"),
			wantSuffix: "scan-result.json",
		},
		{
			name:       "blank output uses default report name",
			outputFile: filepath.Join(t.TempDir(), "   "),
			wantSuffix: "   .json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewJsonPrinter()
			p.SetWriter(context.Background(), tt.outputFile)
			defer p.writer.Close()

			assert.True(t, strings.HasSuffix(p.writer.Name(), tt.wantSuffix), p.writer.Name())
		})
	}
}

func TestJsonPrinterSetWriterUsesStdoutForEmptyOutput(t *testing.T) {
	p := NewJsonPrinter()

	p.SetWriter(context.Background(), "")

	assert.Equal(t, os.Stdout.Name(), p.writer.Name())
}

func TestPrometheusPrinterPrintDetails(t *testing.T) {
	tests := []struct {
		name        string
		resources   []string
		wantLines   []string
		notWantLine string
	}{
		{
			name:      "prints namespaced resource count",
			resources: []string{"deploy-1", "deploy-1", "pod-1"},
			wantLines: []string{
				`kubescape_object_failed_count{framework="fw",control="ctrl",namespace="default",name="api",groupVersionKind="apps/v1/Deployment"} 2`,
				`kubescape_object_failed_count{framework="fw",control="ctrl",namespace="default",name="worker",groupVersionKind="v1/Pod"} 1`,
			},
		},
		{
			name:        "omits namespace label for cluster scoped resource",
			resources:   []string{"node-1"},
			wantLines:   []string{`kubescape_object_failed_count{framework="fw",control="ctrl",name="node-a",groupVersionKind="v1/Node"} 1`},
			notWantLine: `namespace=`,
		},
		{
			name:      "empty resource list prints nothing",
			resources: []string{},
		},
	}

	allResources := map[string]workloadinterface.IMetadata{
		"deploy-1": workload("apps/v1", "Deployment", "default", "api"),
		"pod-1":    workload("v1", "Pod", "default", "worker"),
		"node-1":   workload("v1", "Node", "", "node-a"),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outputFile := filepath.Join(t.TempDir(), "prometheus.out")
			writer, err := os.Create(outputFile)
			require.NoError(t, err)

			p := NewPrometheusPrinter(false)
			p.writer = writer
			p.printDetails(allResources, tt.resources, "fw", "ctrl", "failed")
			require.NoError(t, writer.Close())

			got, err := os.ReadFile(outputFile)
			require.NoError(t, err)
			for _, want := range tt.wantLines {
				assert.Contains(t, string(got), want)
			}
			if tt.notWantLine != "" {
				assert.NotContains(t, string(got), tt.notWantLine)
			}
			if len(tt.resources) == 0 {
				assert.Empty(t, strings.TrimSpace(string(got)))
			}
		})
	}
}

func TestNewPrometheusPrinterStoresVerboseMode(t *testing.T) {
	assert.False(t, NewPrometheusPrinter(false).verboseMode)
	assert.True(t, NewPrometheusPrinter(true).verboseMode)
}

func workload(apiVersion, kind, namespace, name string) workloadinterface.IMetadata {
	return workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata": map[string]any{
			"namespace": namespace,
			"name":      name,
		},
	})
}
