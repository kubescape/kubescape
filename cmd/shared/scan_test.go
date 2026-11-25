package shared

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
	"github.com/kubescape/kubescape/v4/pkg/imagescan"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateScanFormat(t *testing.T) {
	testCases := []struct {
		Description string
		Format      string
		Supported   []string
		WantErr     bool
	}{
		{"valid single format", "json", ScanFormats, false},
		{"valid default format", "pretty-printer", ScanFormats, false},
		{"valid comma-separated formats", "json,html,junit", ScanFormats, false},
		{"comma-separated with whitespace and empty entry", "json, ,html", ScanFormats, false},
		{"empty string is not an invalid format", "", ScanFormats, false},
		{"separator-only input is rejected", ",", ScanFormats, true},
		{"whitespace-and-separator-only input is rejected", " , ", ScanFormats, true},
		{"invalid format", "xml", ScanFormats, true},
		{"mixed valid and invalid formats", "json,xml", ScanFormats, true},
		{"valid image format", "sarif", ScanFormats, false},
		{"junit format is now supported for image scanning", "junit", ScanFormats, false},
		{"junit is supported for image scanning", "junit", ImageScanFormats, false},
		{"csv is supported for image scanning", "csv", ImageScanFormats, false},
		{"policyreport is supported for image scanning", "policyreport", ImageScanFormats, false},
		{"gitlab-container-scanning is supported for image scanning", "gitlab-container-scanning", ImageScanFormats, false},
		{"github-actions is supported for image scanning", "github-actions", ImageScanFormats, false},
		{"gitlab-codequality is not supported for image scanning", "gitlab-codequality", ImageScanFormats, true},
		{"uppercase single format is accepted", "JSON", ScanFormats, false},
		{"mixed-case comma-separated formats with whitespace", " JSON , Yaml,SARIF ", ScanFormats, false},
		{"uppercase invalid format is rejected", "XML", ScanFormats, true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Description, func(t *testing.T) {
			err := ValidateScanFormat(testCase.Format, testCase.Supported)
			if testCase.WantErr {
				if err == nil {
					t.Errorf("expected an error for format %q, got nil", testCase.Format)
				}
			} else if err != nil {
				t.Errorf("expected no error for format %q, got: %v", testCase.Format, err)
			}
		})
	}
}

func TestNormalizeScanFormats(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty string", "", ""},
		{"whitespace only", "   ", ""},
		{"single lowercase", "json", "json"},
		{"single uppercase", "JSON", "json"},
		{"padded uppercase", " YAML ", "yaml"},
		{"mixed comma-separated with padding", " JSON , Yaml,SARIF ", "json,yaml,sarif"},
		{"drops empty tokens", "json,,html, ", "json,html"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeScanFormats(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestValidateView(t *testing.T) {
	testCases := []struct {
		description string
		view        string
		wantErr     bool
		errMsg      string
	}{
		{"valid resource view", "resource", false, ""},
		{"valid control view", "control", false, ""},
		{"valid security view", "security", false, ""},
		{"valid namespace view", "namespace", false, ""},
		{"valid mixed-case view", "Resource", false, ""},
		{"valid uppercase view", "CONTROL", false, ""},
		{"valid padded view", "  security  ", false, ""},
		{"empty view", "", true, "view cannot be empty"},
		{"whitespace-only view", "   ", true, "view cannot be empty"},
		{"plural controls typo", "controls", true, "invalid view \"controls\""},
		{"plural resources typo", "resources", true, "invalid view \"resources\""},
		{"unsupported view", "table", true, "invalid view \"table\""},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			err := ValidateView(tc.view)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateSeverity(t *testing.T) {
	testCases := []struct {
		Description string
		Input       string
		Want        error
	}{
		{"low should be a valid severity", "low", nil},
		{"Low should be a valid severity", "Low", nil},
		{"medium should be a valid severity", "medium", nil},
		{"Medium should be a valid severity", "Medium", nil},
		{"high should be a valid severity", "high", nil},
		{"Critical should be a valid severity", "Critical", nil},
		{"critical should be a valid severity", "critical", nil},
		{"Unknown should be an invalid severity", "Unknown", ErrUnknownSeverity},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Description, func(t *testing.T) {
			input := testCase.Input
			want := testCase.Want
			got := ValidateSeverity(input)

			if got != want {
				t.Errorf("got: %v, want: %v", got, want)
			}
		})
	}
}

func TestValidateThreshold(t *testing.T) {
	testCases := []struct {
		Description string
		Value       float32
		WantErr     string
	}{
		{"0 is valid", 0, ""},
		{"100 is valid", 100, ""},
		{"above 100 names the flag, range and value", 150, "bad argument: out of range threshold: --compliance-threshold must be between 0 and 100, got 150"},
		{"below 0 names the flag, range and value", -5, "bad argument: out of range threshold: --compliance-threshold must be between 0 and 100, got -5"},
		{"NaN names the flag, range and value", float32(math.NaN()), "bad argument: out of range threshold: --compliance-threshold must be between 0 and 100, got NaN"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Description, func(t *testing.T) {
			err := ValidateThreshold("compliance-threshold", testCase.Value)
			if testCase.WantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, ErrBadThreshold)
			assert.EqualError(t, err, testCase.WantErr)
		})
	}
}

func TestValidateThresholdsNamesOffendingFlag(t *testing.T) {
	testCases := []struct {
		Description string
		ScanInfo    *cautils.ScanInfo
		WantFlag    string
	}{
		{"fail threshold", &cautils.ScanInfo{FailThreshold: 101}, "--fail-threshold"},
		{"compliance threshold", &cautils.ScanInfo{ComplianceThreshold: 101}, "--compliance-threshold"},
		{"coverage threshold", &cautils.ScanInfo{FailCoverageThreshold: 101}, "--fail-coverage-below"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Description, func(t *testing.T) {
			err := ValidateThresholds(testCase.ScanInfo)
			require.ErrorIs(t, err, ErrBadThreshold)
			assert.ErrorContains(t, err, testCase.WantFlag+" must be between 0 and 100, got 101")
		})
	}
}

func TestValidateCommonScanFlags(t *testing.T) {
	tests := []struct {
		name          string
		severity      string
		minSeverity   string
		maxSeverity   string
		format        string
		formatChanged bool
		submit        bool
		local         bool
		omitRaw       bool
		expectedErr   string
	}{
		{
			name:          "Valid setup",
			severity:      "High",
			minSeverity:   "Medium",
			format:        "json",
			formatChanged: true,
			expectedErr:   "",
		},
		{
			name:          "Invalid severity",
			severity:      "Extreme",
			format:        "json",
			formatChanged: true,
			expectedErr:   "unknown severity",
		},
		{
			name:          "Invalid minimum severity",
			severity:      "High",
			minSeverity:   "Extreme",
			format:        "json",
			formatChanged: true,
			expectedErr:   "unknown severity",
		},
		{
			name:          "Empty format flag explicitly passed",
			severity:      "High",
			format:        "",
			formatChanged: true,
			expectedErr:   "format cannot be empty, supported formats",
		},
		{
			name:          "Whitespace-only format flag explicitly passed",
			severity:      "High",
			format:        "   ",
			formatChanged: true,
			expectedErr:   "format cannot be empty, supported formats",
		},
		{
			name:          "Invalid format",
			severity:      "High",
			format:        "fake-format",
			formatChanged: true,
			expectedErr:   "invalid format",
		},
		{
			name:          "Submit with keep-local",
			submit:        true,
			local:         true,
			format:        "json",
			formatChanged: true,
			expectedErr:   "you can use `keep-local` or `submit`, but not both",
		},
		{
			name:          "Submit with omit-raw-resources",
			submit:        true,
			omitRaw:       true,
			format:        "json",
			formatChanged: true,
			expectedErr:   "you can use `omit-raw-resources` or `submit`, but not both",
		},
		{
			name:          "Valid max severity",
			severity:      "High",
			maxSeverity:   "Critical",
			format:        "json",
			formatChanged: true,
			expectedErr:   "",
		},
		{
			name:          "Invalid max severity",
			severity:      "High",
			maxSeverity:   "Extreme",
			format:        "json",
			formatChanged: true,
			expectedErr:   "unknown severity",
		},
		{
			name:          "Valid min and max severity range",
			minSeverity:   "Medium",
			maxSeverity:   "High",
			format:        "json",
			formatChanged: true,
			expectedErr:   "",
		},
		{
			name:          "Invalid min and max severity range",
			minSeverity:   "High",
			maxSeverity:   "Medium",
			format:        "json",
			formatChanged: true,
			expectedErr:   "min severity cannot be greater than max severity",
		},
		{
			name:          "Min equals max severity",
			minSeverity:   "High",
			maxSeverity:   "High",
			format:        "json",
			formatChanged: true,
			expectedErr:   "",
		},
		{
			name:          "Padded min severity accepted",
			minSeverity:   "  high  ",
			format:        "json",
			formatChanged: true,
			expectedErr:   "",
		},
		{
			name:          "Padded max severity accepted and normalized",
			maxSeverity:   "  critical  ",
			format:        "json",
			formatChanged: true,
			expectedErr:   "",
		},
		{
			name:          "Padded and mixed-case severities normalized",
			severity:      "  HIGH  ",
			minSeverity:   "  medium ",
			maxSeverity:   " Critical ",
			format:        "json",
			formatChanged: true,
			expectedErr:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanInfo := &cautils.ScanInfo{
				FailThresholdSeverity: tt.severity,
				MinSeverity:           tt.minSeverity,
				MaxSeverity:           tt.maxSeverity,
				Format:                tt.format,
				Local:                 tt.local,
				OmitRawResources:      tt.omitRaw,
				Submit:                cautils.NewBoolPtr(&tt.submit),
			}

			cmd := &cobra.Command{}
			cmd.Flags().String("format", "", "")
			if tt.formatChanged {
				cmd.Flags().Set("format", tt.format)
			}

			err := ValidateCommonScanFlags(cmd, scanInfo, ScanFormats)

			if tt.expectedErr == "" {
				assert.NoError(t, err)
				if tt.severity != "" {
					assert.Equal(t, strings.ToLower(strings.TrimSpace(tt.severity)), scanInfo.FailThresholdSeverity)
				}
				if tt.minSeverity != "" {
					assert.Equal(t, strings.ToLower(strings.TrimSpace(tt.minSeverity)), scanInfo.MinSeverity)
				}
				if tt.maxSeverity != "" {
					assert.Equal(t, strings.ToLower(strings.TrimSpace(tt.maxSeverity)), scanInfo.MaxSeverity)
				}
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			}
		})
	}
}

func TestValidateCommonScanFlags_ExplicitEmptySeverityFlags(t *testing.T) {
	tests := []struct {
		name     string
		flagName string
		setup    func(*cobra.Command, *cautils.ScanInfo)
	}{
		{
			name:     "empty --severity-threshold is rejected",
			flagName: "severity-threshold",
			setup: func(cmd *cobra.Command, scanInfo *cautils.ScanInfo) {
				cmd.Flags().StringVar(&scanInfo.FailThresholdSeverity, "severity-threshold", "", "")
				_ = cmd.Flags().Set("severity-threshold", "")
			},
		},
		{
			name:     "whitespace --severity-threshold is rejected",
			flagName: "severity-threshold",
			setup: func(cmd *cobra.Command, scanInfo *cautils.ScanInfo) {
				cmd.Flags().StringVar(&scanInfo.FailThresholdSeverity, "severity-threshold", "", "")
				_ = cmd.Flags().Set("severity-threshold", "   ")
			},
		},
		{
			name:     "empty --min-severity is rejected",
			flagName: "min-severity",
			setup: func(cmd *cobra.Command, scanInfo *cautils.ScanInfo) {
				cmd.Flags().StringVar(&scanInfo.MinSeverity, "min-severity", "", "")
				_ = cmd.Flags().Set("min-severity", "")
			},
		},
		{
			name:     "whitespace --min-severity is rejected",
			flagName: "min-severity",
			setup: func(cmd *cobra.Command, scanInfo *cautils.ScanInfo) {
				cmd.Flags().StringVar(&scanInfo.MinSeverity, "min-severity", "", "")
				_ = cmd.Flags().Set("min-severity", "   ")
			},
		},
		{
			name:     "empty --max-severity is rejected",
			flagName: "max-severity",
			setup: func(cmd *cobra.Command, scanInfo *cautils.ScanInfo) {
				cmd.Flags().StringVar(&scanInfo.MaxSeverity, "max-severity", "", "")
				_ = cmd.Flags().Set("max-severity", "")
			},
		},
		{
			name:     "whitespace --max-severity is rejected",
			flagName: "max-severity",
			setup: func(cmd *cobra.Command, scanInfo *cautils.ScanInfo) {
				cmd.Flags().StringVar(&scanInfo.MaxSeverity, "max-severity", "", "")
				_ = cmd.Flags().Set("max-severity", "   ")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanInfo := &cautils.ScanInfo{}
			cmd := &cobra.Command{}
			tt.setup(cmd, scanInfo)

			err := ValidateCommonScanFlags(cmd, scanInfo, ScanFormats)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrUnknownSeverity)
		})
	}
}

func TestValidateCommonScanFlags_View(t *testing.T) {
	tests := []struct {
		name        string
		scanType    cautils.ScanTypes
		view        string
		viewChanged bool
		expectedErr string
		wantView    string
	}{
		{
			name:        "Valid view normalized to lowercase",
			view:        "Resource",
			viewChanged: true,
			wantView:    "resource",
		},
		{
			name:        "Valid security view",
			view:        "security",
			viewChanged: true,
			wantView:    "security",
		},
		{
			name:        "Valid control view",
			view:        "control",
			viewChanged: true,
			wantView:    "control",
		},
		{
			name:        "Valid namespace view",
			view:        "namespace",
			viewChanged: true,
			wantView:    "namespace",
		},
		{
			name:        "Invalid view rejected",
			view:        "controls",
			viewChanged: true,
			expectedErr: "invalid view \"controls\", supported views: resource, control, security, namespace",
		},
		{
			name:        "Explicit empty view rejected",
			view:        "",
			viewChanged: true,
			expectedErr: "view cannot be empty, supported views: resource, control, security, namespace",
		},
		{
			name:        "Explicit whitespace view rejected",
			view:        "   ",
			viewChanged: true,
			expectedErr: "view cannot be empty, supported views: resource, control, security, namespace",
		},
		{
			name:        "View flag on image scan rejected",
			scanType:    cautils.ScanTypeImage,
			view:        "resource",
			viewChanged: true,
			expectedErr: "--view is not supported for image scans: an image scan evaluates vulnerabilities, not posture views",
		},
		{
			name:        "Default view on image scan accepted when not explicitly changed",
			scanType:    cautils.ScanTypeImage,
			view:        "security",
			viewChanged: false,
			wantView:    "security",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanInfo := &cautils.ScanInfo{
				ScanType: tt.scanType,
				View:     tt.view,
			}

			cmd := &cobra.Command{}
			cmd.Flags().String("view", "security", "")
			if tt.viewChanged {
				cmd.Flags().Set("view", tt.view)
			}

			err := ValidateCommonScanFlags(cmd, scanInfo, ScanFormats)

			if tt.expectedErr == "" {
				require.NoError(t, err)
				if tt.wantView != "" {
					assert.Equal(t, tt.wantView, scanInfo.View)
				}
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			}
		})
	}
}

func TestValidateCommonScanFlagsImageRiskGates(t *testing.T) {
	tests := []struct {
		name        string
		scanInfo    cautils.ScanInfo
		expectedErr string
	}{
		{name: "gates unset on a posture scan", scanInfo: cautils.ScanInfo{}},
		{name: "KEV gate on an image scan", scanInfo: cautils.ScanInfo{FailOnKEV: true, ScanType: cautils.ScanTypeImage}},
		{name: "EPSS gate with --scan-images", scanInfo: cautils.ScanInfo{EPSSThreshold: 0.5, ScanImages: true}},
		{name: "EPSS threshold of 1", scanInfo: cautils.ScanInfo{EPSSThreshold: 1, ScanImages: true}},
		{name: "EPSS threshold of 0 disables the gate on a posture scan", scanInfo: cautils.ScanInfo{EPSSThreshold: 0}},
		{
			name:        "KEV gate on a posture scan without images",
			scanInfo:    cautils.ScanInfo{FailOnKEV: true},
			expectedErr: "--fail-on-kev evaluates image vulnerabilities: use 'kubescape scan image' or add --scan-images",
		},
		{
			name:        "EPSS gate on a posture scan without images",
			scanInfo:    cautils.ScanInfo{EPSSThreshold: 0.3},
			expectedErr: "--epss-threshold evaluates image vulnerabilities: use 'kubescape scan image' or add --scan-images",
		},
		{name: "dry run with --scan-images and gates unset", scanInfo: cautils.ScanInfo{DryRun: true, ScanImages: true}},
		{
			name:        "KEV gate on a dry run with --scan-images",
			scanInfo:    cautils.ScanInfo{DryRun: true, ScanImages: true, FailOnKEV: true},
			expectedErr: "--fail-on-kev cannot be used with --dry-run: a dry run does not scan images",
		},
		{
			name:        "EPSS gate on a dry run with --scan-images",
			scanInfo:    cautils.ScanInfo{DryRun: true, ScanImages: true, EPSSThreshold: 0.2},
			expectedErr: "--epss-threshold cannot be used with --dry-run: a dry run does not scan images",
		},
		{
			name:        "EPSS threshold above 1",
			scanInfo:    cautils.ScanInfo{EPSSThreshold: 1.5, ScanImages: true},
			expectedErr: "bad argument: out of range threshold: --epss-threshold must be between 0 and 1, got 1.5",
		},
		{
			name:        "negative EPSS threshold",
			scanInfo:    cautils.ScanInfo{EPSSThreshold: -0.1, ScanImages: true},
			expectedErr: "bad argument: out of range threshold: --epss-threshold must be between 0 and 1, got -0.1",
		},
		{
			name:        "NaN EPSS threshold",
			scanInfo:    cautils.ScanInfo{EPSSThreshold: math.NaN(), ScanImages: true},
			expectedErr: "bad argument: out of range threshold: --epss-threshold must be between 0 and 1, got NaN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCommonScanFlags(&cobra.Command{}, &tt.scanInfo, ScanFormats)
			if tt.expectedErr == "" {
				assert.NoError(t, err)
				return
			}
			require.EqualError(t, err, tt.expectedErr)
			if strings.Contains(tt.expectedErr, "out of range") {
				assert.ErrorIs(t, err, ErrBadThreshold)
			}
		})
	}
}

func TestApplyDBAgeGatePresence(t *testing.T) {
	newCmd := func() *cobra.Command {
		cmd := &cobra.Command{}
		cmd.Flags().Bool("fail-on-stale-db", false, "")
		cmd.Flags().Duration("max-db-age", 0, "")
		return cmd
	}

	t.Run("unset flags leave presence false", func(t *testing.T) {
		scanInfo := &cautils.ScanInfo{}
		ApplyDBAgeGatePresence(newCmd(), scanInfo)
		assert.False(t, scanInfo.FailOnStaleDBSet)
		assert.False(t, scanInfo.MaxDBAgeSet)
	})

	t.Run("explicit false and zero mark presence", func(t *testing.T) {
		cmd := newCmd()
		require.NoError(t, cmd.Flags().Set("fail-on-stale-db", "false"))
		require.NoError(t, cmd.Flags().Set("max-db-age", "0s"))
		scanInfo := &cautils.ScanInfo{}
		ApplyDBAgeGatePresence(cmd, scanInfo)
		assert.True(t, scanInfo.FailOnStaleDBSet)
		assert.True(t, scanInfo.MaxDBAgeSet)
	})

	t.Run("explicit values beat conflicting env end to end", func(t *testing.T) {
		t.Setenv("KS_FAIL_ON_STALE_DB", "true")
		t.Setenv("KS_MAX_DB_AGE", "2160h")
		cmd := newCmd()
		require.NoError(t, cmd.Flags().Set("fail-on-stale-db", "false"))
		require.NoError(t, cmd.Flags().Set("max-db-age", "0s"))
		scanInfo := &cautils.ScanInfo{}
		require.NoError(t, ValidateCommonScanFlags(cmd, scanInfo, ScanFormats))
		fail, maxAge := imagescan.ResolveDBAgeGate(scanInfo.FailOnStaleDB, scanInfo.FailOnStaleDBSet, scanInfo.MaxDBAge, scanInfo.MaxDBAgeSet)
		assert.False(t, fail, "explicit --fail-on-stale-db=false must win over env true")
		assert.Equal(t, time.Duration(0), maxAge, "explicit --max-db-age=0 must win over env 2160h")
	})
}

func TestValidateKindFilters(t *testing.T) {
	tests := []struct {
		name         string
		includeKinds string
		excludeKinds string
		expectedErr  string
	}{
		{
			name:         "both empty is valid",
			includeKinds: "",
			excludeKinds: "",
			expectedErr:  "",
		},
		{
			name:         "valid include-kinds",
			includeKinds: "Deployment,DaemonSet",
			excludeKinds: "",
			expectedErr:  "",
		},
		{
			name:         "valid exclude-kinds",
			includeKinds: "",
			excludeKinds: "Job,CronJob",
			expectedErr:  "",
		},
		{
			name:         "both set is valid",
			includeKinds: "Deployment",
			excludeKinds: "DaemonSet",
			expectedErr:  "",
		},
		{
			name:         "include-kinds whitespace-only tokens are rejected",
			includeKinds: " , , ",
			excludeKinds: "",
			expectedErr:  "contains no valid kind names",
		},
		{
			name:         "exclude-kinds whitespace-only tokens are rejected",
			includeKinds: "",
			excludeKinds: "  ,  ",
			expectedErr:  "contains no valid kind names",
		},
		{
			name:         "single valid kind in include",
			includeKinds: "Pod",
			excludeKinds: "",
			expectedErr:  "",
		},
		{
			name:         "padded valid kind passes",
			includeKinds: "  Deployment  ",
			excludeKinds: "",
			expectedErr:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanInfo := &cautils.ScanInfo{
				IncludeKinds: tt.includeKinds,
				ExcludeKinds: tt.excludeKinds,
			}
			err := ValidateKindFilters(scanInfo)
			if tt.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			}
		})
	}
}

func TestValidateNamespaceFilters(t *testing.T) {
	tests := []struct {
		name              string
		includeNamespaces string
		excludeNamespaces string
		expectedErr       string
	}{
		{
			name:              "both empty is valid",
			includeNamespaces: "",
			excludeNamespaces: "",
			expectedErr:       "",
		},
		{
			name:              "valid include-namespaces",
			includeNamespaces: "default,kube-system",
			excludeNamespaces: "",
			expectedErr:       "",
		},
		{
			name:              "valid exclude-namespaces",
			includeNamespaces: "",
			excludeNamespaces: "kube-system,kube-public",
			expectedErr:       "",
		},
		{
			name:              "include-namespaces whitespace-only tokens are rejected",
			includeNamespaces: " , , ",
			excludeNamespaces: "",
			expectedErr:       "contains no valid namespace names",
		},
		{
			name:              "exclude-namespaces whitespace-only tokens are rejected",
			includeNamespaces: "",
			excludeNamespaces: "  ,  ",
			expectedErr:       "contains no valid namespace names",
		},
		{
			name:              "single valid namespace passes",
			includeNamespaces: "prod",
			excludeNamespaces: "",
			expectedErr:       "",
		},
		{
			name:              "padded valid namespace passes",
			includeNamespaces: "  prod  ",
			excludeNamespaces: "",
			expectedErr:       "",
		},
		{
			name:              "wildcard namespace passes",
			includeNamespaces: "*",
			excludeNamespaces: "",
			expectedErr:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanInfo := &cautils.ScanInfo{
				IncludeNamespaces:  tt.includeNamespaces,
				ExcludedNamespaces: tt.excludeNamespaces,
			}
			err := ValidateNamespaceFilters(scanInfo)
			if tt.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			}
		})
	}
}

func TestValidateCommonScanFlags_NamespaceFilters(t *testing.T) {
	tests := []struct {
		name        string
		flagName    string
		flagVal     string
		setFlag     bool
		setInfo     func(*cautils.ScanInfo, string)
		expectedErr string
	}{
		{
			name:     "omitted include-namespaces is valid",
			flagName: "include-namespaces",
			setFlag:  false,
			setInfo:  func(s *cautils.ScanInfo, v string) { s.IncludeNamespaces = v },
		},
		{
			name:     "omitted exclude-namespaces is valid",
			flagName: "exclude-namespaces",
			setFlag:  false,
			setInfo:  func(s *cautils.ScanInfo, v string) { s.ExcludedNamespaces = v },
		},
		{
			name:        "explicit empty include-namespaces is rejected",
			flagName:    "include-namespaces",
			flagVal:     "",
			setFlag:     true,
			setInfo:     func(s *cautils.ScanInfo, v string) { s.IncludeNamespaces = v },
			expectedErr: `--include-namespaces value "" contains no valid namespace names`,
		},
		{
			name:        "explicit whitespace include-namespaces is rejected",
			flagName:    "include-namespaces",
			flagVal:     "   ",
			setFlag:     true,
			setInfo:     func(s *cautils.ScanInfo, v string) { s.IncludeNamespaces = v },
			expectedErr: `--include-namespaces value "   " contains no valid namespace names`,
		},
		{
			name:        "explicit empty exclude-namespaces is rejected",
			flagName:    "exclude-namespaces",
			flagVal:     "",
			setFlag:     true,
			setInfo:     func(s *cautils.ScanInfo, v string) { s.ExcludedNamespaces = v },
			expectedErr: `--exclude-namespaces value "" contains no valid namespace names`,
		},
		{
			name:        "explicit whitespace exclude-namespaces is rejected",
			flagName:    "exclude-namespaces",
			flagVal:     "   ",
			setFlag:     true,
			setInfo:     func(s *cautils.ScanInfo, v string) { s.ExcludedNamespaces = v },
			expectedErr: `--exclude-namespaces value "   " contains no valid namespace names`,
		},
		{
			name:     "valid include-namespaces passes",
			flagName: "include-namespaces",
			flagVal:  "default",
			setFlag:  true,
			setInfo:  func(s *cautils.ScanInfo, v string) { s.IncludeNamespaces = v },
		},
		{
			name:     "valid exclude-namespaces passes",
			flagName: "exclude-namespaces",
			flagVal:  "kube-system",
			setFlag:  true,
			setInfo:  func(s *cautils.ScanInfo, v string) { s.ExcludedNamespaces = v },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &cautils.ScanInfo{Format: "json"}
			tt.setInfo(info, tt.flagVal)
			cmd := &cobra.Command{}
			cmd.Flags().String(tt.flagName, "", "")
			if tt.setFlag {
				require.NoError(t, cmd.Flags().Set(tt.flagName, tt.flagVal))
			}
			err := ValidateCommonScanFlags(cmd, info, ScanFormats)
			if tt.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.expectedErr)
			}
		})
	}
}

func TestValidateExcludePaths(t *testing.T) {
	tests := []struct {
		name         string
		excludePaths []string
		expectedErr  string
	}{
		{
			name:         "no patterns is valid",
			excludePaths: nil,
			expectedErr:  "",
		},
		{
			name:         "gitignore syntax is accepted",
			excludePaths: []string{"test/**", "!test/prod.yaml", "/vendor/", "*.tmpl.yaml"},
			expectedErr:  "",
		},
		{
			name:         "a comment typed as an argument is rejected",
			excludePaths: []string{"# a comment"},
			expectedErr:  "carries no rule",
		},
		{
			name:         "a blank argument is rejected",
			excludePaths: []string{"  "},
			expectedErr:  "carries no rule",
		},
		{
			name:         "an anchored pattern is still accepted",
			excludePaths: []string{"/vendor"},
			expectedErr:  "",
		},
		{
			name:         "unclosed character class is rejected",
			excludePaths: []string{"pod[.yaml"},
			expectedErr:  "invalid exclusion pattern",
		},
		{
			name:         "pattern with nothing to match is rejected",
			excludePaths: []string{"!"},
			expectedErr:  "exclusion pattern is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateExcludePaths(&cautils.ScanInfo{ExcludePaths: tt.excludePaths})
			if tt.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			}
		})
	}
}

// Commas are significant inside a glob alternation, so --exclude-path must not split
// on them the way a comma-separated flag would.
func TestValidateExcludePathsAcceptsBraceAlternation(t *testing.T) {
	err := ValidateExcludePaths(&cautils.ScanInfo{ExcludePaths: []string{"*.{yaml,json}"}})
	assert.NoError(t, err)
}

func TestValidateExcludeControls(t *testing.T) {
	tests := []struct {
		name            string
		excludeControls []string
		expectedErr     string
	}{
		{
			name:            "no controls is valid",
			excludeControls: nil,
			expectedErr:     "",
		},
		{
			name:            "control ids are valid",
			excludeControls: []string{"C-0016", "C-0017"},
			expectedErr:     "",
		},
		{
			name:            "a control name is valid",
			excludeControls: []string{"Immutable container filesystem"},
			expectedErr:     "",
		},
		{
			name:            "an empty identifier is rejected",
			excludeControls: []string{"C-0016", "  "},
			expectedErr:     "empty control identifier",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateExcludeControls(&cautils.ScanInfo{ExcludeControls: tt.excludeControls})
			if tt.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			}
		})
	}
}

func TestValidateControlFilters(t *testing.T) {
	tests := []struct {
		name        string
		include     string
		skip        string
		expectedErr string
	}{
		{
			name:        "empty filters are valid",
			include:     "",
			skip:        "",
			expectedErr: "",
		},
		{
			name:        "valid single and comma-separated controls",
			include:     "C-0016,C-0017",
			skip:        "C-0018",
			expectedErr: "",
		},
		{
			name:        "padded control IDs are valid",
			include:     " C-0016 , C-0017 ",
			skip:        " C-0018 ",
			expectedErr: "",
		},
		{
			name:        "include controls with empty token is rejected",
			include:     "C-0016,",
			expectedErr: "--include-controls contains an empty control identifier",
		},
		{
			name:        "include controls with whitespace-only token is rejected",
			include:     "C-0016,   ,C-0017",
			expectedErr: "--include-controls contains an empty control identifier",
		},
		{
			name:        "include controls whitespace only is rejected",
			include:     "   ",
			expectedErr: "--include-controls contains an empty control identifier",
		},
		{
			name:        "skip controls with empty token is rejected",
			skip:        "C-0016,",
			expectedErr: "--skip-controls contains an empty control identifier",
		},
		{
			name:        "skip controls with whitespace-only token is rejected",
			skip:        "C-0016,   ",
			expectedErr: "--skip-controls contains an empty control identifier",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateControlFilters(&cautils.ScanInfo{
				IncludeControls: tt.include,
				SkipControls:    tt.skip,
			})
			if tt.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			}
		})
	}
}

func TestValidateCommonScanFlags_ControlFilters(t *testing.T) {
	tests := []struct {
		name        string
		flagName    string
		flagVal     string
		setFlag     bool
		setInfo     func(*cautils.ScanInfo, string)
		expectedErr string
	}{
		{
			name:     "omitted include-controls is valid",
			flagName: "include-controls",
			setFlag:  false,
			setInfo:  func(s *cautils.ScanInfo, v string) { s.IncludeControls = v },
		},
		{
			name:     "omitted skip-controls is valid",
			flagName: "skip-controls",
			setFlag:  false,
			setInfo:  func(s *cautils.ScanInfo, v string) { s.SkipControls = v },
		},
		{
			name:        "explicit empty include-controls is rejected",
			flagName:    "include-controls",
			flagVal:     "",
			setFlag:     true,
			setInfo:     func(s *cautils.ScanInfo, v string) { s.IncludeControls = v },
			expectedErr: "--include-controls contains an empty control identifier",
		},
		{
			name:        "explicit whitespace include-controls is rejected",
			flagName:    "include-controls",
			flagVal:     "   ",
			setFlag:     true,
			setInfo:     func(s *cautils.ScanInfo, v string) { s.IncludeControls = v },
			expectedErr: "--include-controls contains an empty control identifier",
		},
		{
			name:        "explicit empty skip-controls is rejected",
			flagName:    "skip-controls",
			flagVal:     "",
			setFlag:     true,
			setInfo:     func(s *cautils.ScanInfo, v string) { s.SkipControls = v },
			expectedErr: "--skip-controls contains an empty control identifier",
		},
		{
			name:        "explicit whitespace skip-controls is rejected",
			flagName:    "skip-controls",
			flagVal:     "   ",
			setFlag:     true,
			setInfo:     func(s *cautils.ScanInfo, v string) { s.SkipControls = v },
			expectedErr: "--skip-controls contains an empty control identifier",
		},
		{
			name:     "valid include-controls passes",
			flagName: "include-controls",
			flagVal:  "C-0016",
			setFlag:  true,
			setInfo:  func(s *cautils.ScanInfo, v string) { s.IncludeControls = v },
		},
		{
			name:     "valid skip-controls passes",
			flagName: "skip-controls",
			flagVal:  "C-0016",
			setFlag:  true,
			setInfo:  func(s *cautils.ScanInfo, v string) { s.SkipControls = v },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &cautils.ScanInfo{Format: "json"}
			tt.setInfo(info, tt.flagVal)
			cmd := &cobra.Command{}
			cmd.Flags().String(tt.flagName, "", "")
			if tt.setFlag {
				require.NoError(t, cmd.Flags().Set(tt.flagName, tt.flagVal))
			}
			err := ValidateCommonScanFlags(cmd, info, ScanFormats)
			if tt.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.expectedErr)
			}
		})
	}
}

func TestValidateLabelSelector(t *testing.T) {
	tests := []struct {
		name          string
		labelSelector string
		expectedErr   string
	}{
		{name: "empty selector is accepted", labelSelector: "", expectedErr: ""},
		{name: "simple key=value is accepted", labelSelector: "app=nginx", expectedErr: ""},
		{name: "multiple selectors are accepted", labelSelector: "app=nginx,env!=dev", expectedErr: ""},
		{name: "set-based selector is accepted", labelSelector: "env in (prod,staging)", expectedErr: ""},
		{name: "invalid selector is rejected", labelSelector: "invalid!!selector", expectedErr: "invalid --label-selector"},
		{name: "invalid operator is rejected", labelSelector: "app==nginx==bad", expectedErr: "invalid --label-selector"},
		{name: "whitespace-only selector is rejected", labelSelector: "   ", expectedErr: "invalid --label-selector"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			cmd.Flags().String("format", "", "")
			scanInfo := &cautils.ScanInfo{LabelSelector: tt.labelSelector, Format: "pretty-printer"}
			err := ValidateCommonScanFlags(cmd, scanInfo, ScanFormats)
			if tt.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			}
		})
	}
}

func TestValidateCommonScanFlags_SBOMFormats(t *testing.T) {
	tests := []struct {
		name        string
		format      string
		scanType    cautils.ScanTypes
		scanImages  bool
		expectedErr string
	}{
		{
			name:        "cyclonedx-json without image scanning is rejected",
			format:      printer.CycloneDXFormat,
			scanType:    cautils.ScanTypeCluster,
			scanImages:  false,
			expectedErr: "format \"cyclonedx-json\" requires scanned images: add --scan-images, or run \"kubescape scan image\" to scan an image directly",
		},
		{
			name:        "spdx-json without image scanning is rejected",
			format:      printer.SPDXFormat,
			scanType:    cautils.ScanTypeCluster,
			scanImages:  false,
			expectedErr: "format \"spdx-json\" requires scanned images: add --scan-images, or run \"kubescape scan image\" to scan an image directly",
		},
		{
			name:        "comma-separated formats containing cyclonedx-json without image scanning are rejected",
			format:      "json,cyclonedx-json",
			scanType:    cautils.ScanTypeCluster,
			scanImages:  false,
			expectedErr: "format \"cyclonedx-json\" requires scanned images: add --scan-images, or run \"kubescape scan image\" to scan an image directly",
		},
		{
			name:        "comma-separated formats containing spdx-json without image scanning are rejected",
			format:      "spdx-json,yaml",
			scanType:    cautils.ScanTypeCluster,
			scanImages:  false,
			expectedErr: "format \"spdx-json\" requires scanned images: add --scan-images, or run \"kubescape scan image\" to scan an image directly",
		},
		{
			name:        "whitespace-padded sbom format without image scanning is rejected",
			format:      " json , cyclonedx-json ",
			scanType:    cautils.ScanTypeCluster,
			scanImages:  false,
			expectedErr: "format \"cyclonedx-json\" requires scanned images: add --scan-images, or run \"kubescape scan image\" to scan an image directly",
		},
		{
			name:       "cyclonedx-json on posture scan with --scan-images is accepted",
			format:     printer.CycloneDXFormat,
			scanType:   cautils.ScanTypeCluster,
			scanImages: true,
		},
		{
			name:       "spdx-json on posture scan with --scan-images is accepted",
			format:     printer.SPDXFormat,
			scanType:   cautils.ScanTypeCluster,
			scanImages: true,
		},
		{
			name:       "cyclonedx-json on image scan is accepted",
			format:     printer.CycloneDXFormat,
			scanType:   cautils.ScanTypeImage,
			scanImages: false,
		},
		{
			name:       "spdx-json on image scan is accepted",
			format:     printer.SPDXFormat,
			scanType:   cautils.ScanTypeImage,
			scanImages: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			cmd.Flags().String("format", "", "")
			scanInfo := &cautils.ScanInfo{
				Format:     tt.format,
				ScanImages: tt.scanImages,
				ScanType:   tt.scanType,
			}
			err := ValidateCommonScanFlags(cmd, scanInfo, ScanFormats)
			if tt.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedErr, err.Error())
			}
		})
	}
}

func TestValidateCommonScanFlags_PathFlags(t *testing.T) {
	flags := []struct {
		name    string
		set     func(*cautils.ScanInfo, string)
		get     func(*cautils.ScanInfo) string
		wantErr string
	}{
		{"output", func(s *cautils.ScanInfo, v string) { s.Output = v }, func(s *cautils.ScanInfo) string { return s.Output }, "output file path cannot be empty"},
		{"controls-config", func(s *cautils.ScanInfo, v string) { s.ControlsInputs = v }, func(s *cautils.ScanInfo) string { return s.ControlsInputs }, "--controls-config needs a file path"},
		{"exceptions", func(s *cautils.ScanInfo, v string) { s.UseExceptions = v }, func(s *cautils.ScanInfo) string { return s.UseExceptions }, "--exceptions needs a file path"},
		{"use-artifacts-from", func(s *cautils.ScanInfo, v string) { s.UseArtifactsFrom = v }, func(s *cautils.ScanInfo) string { return s.UseArtifactsFrom }, "--use-artifacts-from needs a directory path"},
		{"custom-rules", func(s *cautils.ScanInfo, v string) { s.CustomRules = v }, func(s *cautils.ScanInfo) string { return s.CustomRules }, "--custom-rules needs a path"},
		{"file-path", func(s *cautils.ScanInfo, v string) { s.FilePath = v }, func(s *cautils.ScanInfo) string { return s.FilePath }, "--file-path needs a file path"},
		{"chart-path", func(s *cautils.ScanInfo, v string) { s.ChartPath = v }, func(s *cautils.ScanInfo) string { return s.ChartPath }, "--chart-path needs a path"},
	}

	for _, f := range flags {
		for _, ws := range []string{"", "   ", "\t\n"} {
			t.Run(f.name+"_whitespace", func(t *testing.T) {
				info := &cautils.ScanInfo{Format: "json"}
				f.set(info, ws)
				cmd := &cobra.Command{}
				cmd.Flags().String(f.name, "", "")
				require.NoError(t, cmd.Flags().Set(f.name, ws))
				err := ValidateCommonScanFlags(cmd, info, ScanFormats)
				require.EqualError(t, err, f.wantErr)
			})
		}
		t.Run(f.name+"_inherited_whitespace", func(t *testing.T) {
			info := &cautils.ScanInfo{Format: "json"}
			f.set(info, "   ")
			parent := &cobra.Command{Use: "parent"}
			child := &cobra.Command{Use: "child"}
			parent.AddCommand(child)
			parent.PersistentFlags().String(f.name, "", "")
			require.NoError(t, parent.PersistentFlags().Set(f.name, "   "))
			err := ValidateCommonScanFlags(child, info, ScanFormats)
			require.EqualError(t, err, f.wantErr)
		})
		t.Run(f.name+"_trims_whitespace", func(t *testing.T) {
			info := &cautils.ScanInfo{Format: "json"}
			f.set(info, "  path/to/target  ")
			cmd := &cobra.Command{}
			cmd.Flags().String(f.name, "", "")
			require.NoError(t, cmd.Flags().Set(f.name, "  path/to/target  "))
			require.NoError(t, ValidateCommonScanFlags(cmd, info, ScanFormats))
			assert.Equal(t, "path/to/target", f.get(info))
		})
	}
}

func TestValidateCommonScanFlags_ExceptionsWithScanImages(t *testing.T) {
	tests := []struct {
		name        string
		format      string
		scanType    cautils.ScanTypes
		scanImages  bool
		expectedErr string
	}{
		{
			name:        "exceptions on posture scan with --scan-images is rejected",
			format:      printer.ExceptionsFormat,
			scanType:    cautils.ScanTypeCluster,
			scanImages:  true,
			expectedErr: "exceptions cannot carry image vulnerabilities; use json or sarif for a combined scan with --scan-images",
		},
		{
			name:        "exceptions on posture scan without --scan-images is accepted",
			format:      printer.ExceptionsFormat,
			scanType:    cautils.ScanTypeCluster,
			scanImages:  false,
			expectedErr: "",
		},
		{
			name:        "comma-separated formats containing exceptions with --scan-images is rejected",
			format:      "json,exceptions",
			scanType:    cautils.ScanTypeCluster,
			scanImages:  true,
			expectedErr: "exceptions cannot carry image vulnerabilities; use json or sarif for a combined scan with --scan-images",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			cmd.Flags().String("format", "", "")
			scanInfo := &cautils.ScanInfo{
				Format:     tt.format,
				ScanImages: tt.scanImages,
				ScanType:   tt.scanType,
			}
			err := ValidateCommonScanFlags(cmd, scanInfo, ScanFormats)
			if tt.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedErr, err.Error())
			}
		})
	}
}
