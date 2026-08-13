package mcpserver

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBuildScanInfo(t *testing.T) {
	tests := []struct {
		name                string
		namespace           string
		wantComplianceScore bool
		expectedNamespace   string
		expectedTimeout     time.Duration
	}{
		{
			name:                "Cluster-wide scan (wildcard)",
			namespace:           "*",
			wantComplianceScore: false,
			expectedNamespace:   "",
			expectedTimeout:     60 * time.Second,
		},
		{
			name:                "Cluster-wide scan (empty string)",
			namespace:           "",
			wantComplianceScore: false,
			expectedNamespace:   "",
			expectedTimeout:     60 * time.Second,
		},
		{
			name:                "Specific namespace scan",
			namespace:           "default",
			wantComplianceScore: false,
			expectedNamespace:   "default",
			expectedTimeout:     10 * time.Second,
		},
		{
			name:                "Cluster-wide scan with compliance score (wildcard)",
			namespace:           "*",
			wantComplianceScore: true,
			expectedNamespace:   "",
			expectedTimeout:     120 * time.Second,
		},
		{
			name:                "Specific namespace scan with compliance score",
			namespace:           "default",
			wantComplianceScore: true,
			expectedNamespace:   "default",
			expectedTimeout:     30 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanInfo := buildScanInfo(tt.namespace, tt.wantComplianceScore, nil)
			assert.Equal(t, tt.expectedNamespace, scanInfo.IncludeNamespaces, "IncludeNamespaces should match")
			assert.Equal(t, tt.expectedTimeout, scanInfo.ScanTimeout, "ScanTimeout should match")
		})
	}
}
