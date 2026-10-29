package scan

import (
	"context"
	"errors"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type riskGateKubescape struct {
	usageThresholdKubescape
	exceeds  bool
	err      error
	scanInfo *cautils.ScanInfo
}

func (m *riskGateKubescape) ScanImageContext(_ context.Context, _ *metav1.ImageScanInfo, scanInfo *cautils.ScanInfo) (bool, error) {
	m.scanInfo = scanInfo
	return m.exceeds, m.err
}

func TestScanImageRiskGateFlags(t *testing.T) {
	ks := &riskGateKubescape{}
	root, _ := newKubescapeRootWithScan(ks)
	root.SetArgs([]string{"scan", "image", "nginx", "--fail-on-kev", "--epss-threshold", "0.3", "--only-fixable"})

	require.NoError(t, root.Execute())
	require.NotNil(t, ks.scanInfo)
	assert.True(t, ks.scanInfo.FailOnKEV)
	assert.Equal(t, 0.3, ks.scanInfo.EPSSThreshold)
	assert.True(t, ks.scanInfo.OnlyFixable)
}

func TestScanImageGateErrors(t *testing.T) {
	gateErr := errors.New("image scan result exceeds exploitability gates: 1 vulnerability match(es) listed in CISA KEV")
	tests := []struct {
		name    string
		exceeds bool
		err     error
		want    string
	}{
		{name: "no gate tripped"},
		{name: "severity threshold only", exceeds: true, want: "result exceeds severity threshold: high"},
		{name: "exploitability gate only", err: gateErr, want: gateErr.Error()},
		{
			name:    "both are reported",
			exceeds: true,
			err:     gateErr,
			want:    gateErr.Error() + "\nresult exceeds severity threshold: high",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks := &riskGateKubescape{exceeds: tt.exceeds, err: tt.err}
			root, buf := newKubescapeRootWithScan(ks)
			root.SetArgs([]string{"scan", "image", "nginx", "--severity-threshold", "high", "--fail-on-kev"})

			err := root.Execute()
			if tt.want == "" {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, tt.want)
			assert.NotContains(t, buf.String(), "Usage:", "gate failure must not dump command usage")
		})
	}
}

func TestScanRiskGateFlagsRequireImages(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "security view", args: []string{"scan", ".", "--fail-on-kev"}, want: "--fail-on-kev evaluates image vulnerabilities"},
		{name: "framework", args: []string{"scan", "framework", "nsa", "--epss-threshold", "0.5"}, want: "--epss-threshold evaluates image vulnerabilities"},
		{name: "control", args: []string{"scan", "control", "C-0058", "--fail-on-kev"}, want: "--fail-on-kev evaluates image vulnerabilities"},
		{name: "out of range on an image scan", args: []string{"scan", "image", "nginx", "--epss-threshold", "1.5"}, want: "--epss-threshold must be between 0 and 1, got 1.5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, _ := newKubescapeRootWithScan(&riskGateKubescape{})
			root.SetArgs(tt.args)

			err := root.Execute()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestScanRiskGateFlagsAcceptedWithImages(t *testing.T) {
	for name, args := range map[string][]string{
		"framework with --scan-images": {"scan", "framework", "nsa", "--scan-images", "--fail-on-kev", "--epss-threshold", "0.5"},
		"workload":                     {"scan", "workload", "Deployment/nginx", "--fail-on-kev"},
	} {
		t.Run(name, func(t *testing.T) {
			root, _ := newKubescapeRootWithScan(&riskGateKubescape{})
			root.SetArgs(args)
			assert.NoError(t, root.Execute())
		})
	}
}
