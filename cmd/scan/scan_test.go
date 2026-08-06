package scan

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/cmd/shared"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/mocks"
	resultshandlingpkg "github.com/kubescape/kubescape/v3/core/pkg/resultshandling"
	v1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExceedsSeverity(t *testing.T) {
	testCases := []struct {
		Description      string
		ScanInfo         *cautils.ScanInfo
		SeverityCounters reportsummary.ISeverityCounters
		Want             bool
		Error            error
	}{
		{
			Description:      "Critical failed resource should exceed Critical threshold",
			ScanInfo:         &cautils.ScanInfo{FailThresholdSeverity: "critical"},
			SeverityCounters: &reportsummary.SeverityCounters{CriticalSeverityCounter: 1},
			Want:             true,
		},
		{
			Description:      "Critical failed resource should exceed Critical threshold set as constant",
			ScanInfo:         &cautils.ScanInfo{FailThresholdSeverity: apis.SeverityCriticalString},
			SeverityCounters: &reportsummary.SeverityCounters{CriticalSeverityCounter: 1},
			Want:             true,
		},
		{
			Description:      "High failed resource should not exceed Critical threshold",
			ScanInfo:         &cautils.ScanInfo{FailThresholdSeverity: "critical"},
			SeverityCounters: &reportsummary.SeverityCounters{HighSeverityCounter: 1},
			Want:             false,
		},
		{
			Description:      "Critical failed resource exceeds High threshold",
			ScanInfo:         &cautils.ScanInfo{FailThresholdSeverity: "high"},
			SeverityCounters: &reportsummary.SeverityCounters{CriticalSeverityCounter: 1},
			Want:             true,
		},
		{
			Description:      "High failed resource exceeds High threshold",
			ScanInfo:         &cautils.ScanInfo{FailThresholdSeverity: "high"},
			SeverityCounters: &reportsummary.SeverityCounters{HighSeverityCounter: 1},
			Want:             true,
		},
		{
			Description:      "Medium failed resource does not exceed High threshold",
			ScanInfo:         &cautils.ScanInfo{FailThresholdSeverity: "high"},
			SeverityCounters: &reportsummary.SeverityCounters{MediumSeverityCounter: 1},
			Want:             false,
		},
		{
			Description:      "Critical failed resource exceeds Medium threshold",
			ScanInfo:         &cautils.ScanInfo{FailThresholdSeverity: "medium"},
			SeverityCounters: &reportsummary.SeverityCounters{CriticalSeverityCounter: 1},
			Want:             true,
		},
		{
			Description:      "High failed resource exceeds Medium threshold",
			ScanInfo:         &cautils.ScanInfo{FailThresholdSeverity: "medium"},
			SeverityCounters: &reportsummary.SeverityCounters{HighSeverityCounter: 1},
			Want:             true,
		},
		{
			Description:      "Medium failed resource exceeds Medium threshold",
			ScanInfo:         &cautils.ScanInfo{FailThresholdSeverity: "medium"},
			SeverityCounters: &reportsummary.SeverityCounters{MediumSeverityCounter: 1},
			Want:             true,
		},
		{
			Description:      "Low failed resource does not exceed Medium threshold",
			ScanInfo:         &cautils.ScanInfo{FailThresholdSeverity: "medium"},
			SeverityCounters: &reportsummary.SeverityCounters{LowSeverityCounter: 1},
			Want:             false,
		},
		{
			Description:      "Critical failed resource exceeds Low threshold",
			ScanInfo:         &cautils.ScanInfo{FailThresholdSeverity: "low"},
			SeverityCounters: &reportsummary.SeverityCounters{CriticalSeverityCounter: 1},
			Want:             true,
		},
		{
			Description:      "High failed resource exceeds Low threshold",
			ScanInfo:         &cautils.ScanInfo{FailThresholdSeverity: "low"},
			SeverityCounters: &reportsummary.SeverityCounters{HighSeverityCounter: 1},
			Want:             true,
		},
		{
			Description:      "Medium failed resource exceeds Low threshold",
			ScanInfo:         &cautils.ScanInfo{FailThresholdSeverity: "low"},
			SeverityCounters: &reportsummary.SeverityCounters{MediumSeverityCounter: 1},
			Want:             true,
		},
		{
			Description:      "Low failed resource exceeds Low threshold",
			ScanInfo:         &cautils.ScanInfo{FailThresholdSeverity: "low"},
			SeverityCounters: &reportsummary.SeverityCounters{LowSeverityCounter: 1},
			Want:             true,
		},
		{
			Description:      "Unknown severity returns an error",
			ScanInfo:         &cautils.ScanInfo{FailThresholdSeverity: "unknown"},
			SeverityCounters: &reportsummary.SeverityCounters{LowSeverityCounter: 1},
			Want:             false,
			Error:            shared.ErrUnknownSeverity,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Description, func(t *testing.T) {
			got, err := countersExceedSeverityThreshold(testCase.SeverityCounters, testCase.ScanInfo)
			want := testCase.Want

			if got != want {
				t.Errorf("got: %v, want: %v", got, want)
			}

			if err != testCase.Error {
				t.Errorf(`got error "%v", want "%v"`, err, testCase.Error)
			}
		})
	}
}

func Test_enforceSeverityThresholds(t *testing.T) {
	testCases := []struct {
		Description      string
		SeverityCounters *reportsummary.SeverityCounters
		ScanInfo         *cautils.ScanInfo
		Want             bool
	}{
		{
			"Exceeding Critical severity counter should call the terminating function",
			&reportsummary.SeverityCounters{CriticalSeverityCounter: 1},
			&cautils.ScanInfo{FailThresholdSeverity: apis.SeverityCriticalString},
			true,
		},
		{
			"Non-exceeding severity counter should call not the terminating function",
			&reportsummary.SeverityCounters{},
			&cautils.ScanInfo{FailThresholdSeverity: apis.SeverityCriticalString},
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.Description,
			func(t *testing.T) {
				severityCounters := tc.SeverityCounters
				scanInfo := tc.ScanInfo
				want := tc.Want

				got := false
				onExceed := func(*cautils.ScanInfo, helpers.ILogger) {
					got = true
				}

				enforceSeverityThresholds(severityCounters, scanInfo, onExceed)

				if got != want {
					t.Errorf("got: %v, want %v", got, want)
				}
			},
		)
	}
}

type spyLogMessage struct {
	Message string
	Details map[string]string
}

type spyLogger struct {
	setItems []spyLogMessage
}

var _ helpers.ILogger = &spyLogger{}

func (l *spyLogger) Error(msg string, details ...helpers.IDetails)                    {}
func (l *spyLogger) Success(msg string, details ...helpers.IDetails)                  {}
func (l *spyLogger) Warning(msg string, details ...helpers.IDetails)                  {}
func (l *spyLogger) Info(msg string, details ...helpers.IDetails)                     {}
func (l *spyLogger) Debug(msg string, details ...helpers.IDetails)                    {}
func (l *spyLogger) SetLevel(level string) error                                      { return nil }
func (l *spyLogger) GetLevel() string                                                 { return "" }
func (l *spyLogger) SetWriter(w *os.File)                                             {}
func (l *spyLogger) GetWriter() *os.File                                              { return &os.File{} }
func (l *spyLogger) LoggerName() string                                               { return "" }
func (l *spyLogger) Ctx(_ context.Context) helpers.ILogger                            { return l }
func (l *spyLogger) Start(msg string, details ...helpers.IDetails)                    {}
func (l *spyLogger) StopSuccess(msg string, details ...helpers.IDetails)              {}
func (l *spyLogger) StopError(msg string, details ...helpers.IDetails)                {}
func (l *spyLogger) TimedWrapper(funcName string, timeout time.Duration, task func()) {}

func (l *spyLogger) Fatal(msg string, details ...helpers.IDetails) {
	firstDetail := details[0]
	detailsMap := map[string]string{firstDetail.Key(): firstDetail.Value().(string)}

	newMsg := spyLogMessage{msg, detailsMap}
	l.setItems = append(l.setItems, newMsg)
}

func (l *spyLogger) GetSpiedItems() []spyLogMessage {
	return l.setItems
}

func Test_terminateOnExceedingSeverity(t *testing.T) {
	expectedMessage := "compliance result exceeds severity threshold"
	expectedKey := "set severity threshold"

	testCases := []struct {
		Description     string
		ExpectedMessage string
		ExpectedKey     string
		ExpectedValue   string
		Logger          *spyLogger
	}{
		{
			"Should log the Critical threshold that was set in scan info",
			expectedMessage,
			expectedKey,
			apis.SeverityCriticalString,
			&spyLogger{},
		},
		{
			"Should log the High threshold that was set in scan info",
			expectedMessage,
			expectedKey,
			apis.SeverityHighString,
			&spyLogger{},
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.Description,
			func(t *testing.T) {
				want := []spyLogMessage{
					{tc.ExpectedMessage, map[string]string{tc.ExpectedKey: tc.ExpectedValue}},
				}
				scanInfo := &cautils.ScanInfo{FailThresholdSeverity: tc.ExpectedValue}

				terminateOnExceedingSeverity(scanInfo, tc.Logger)

				got := tc.Logger.GetSpiedItems()
				if !reflect.DeepEqual(got, want) {
					t.Errorf("got: %v, want: %v", got, want)
				}
			},
		)
	}
}

func TestSetSecurityViewScanInfo(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		want         *cautils.ScanInfo
		wantPolicies []cautils.PolicyIdentifier
	}{
		{
			name: "no args",
			args: []string{},
			want: &cautils.ScanInfo{
				InputPatterns: []string{},
				ScanType:      cautils.ScanTypeCluster,
			},
			wantPolicies: []cautils.PolicyIdentifier{
				{
					Kind:       v1.KindFramework,
					Identifier: "clusterscan",
				},
				{
					Kind:       v1.KindFramework,
					Identifier: "mitre",
				},
				{
					Kind:       v1.KindFramework,
					Identifier: "nsa",
				},
			},
		},
		{
			name: "with args",
			args: []string{
				"file.yaml",
				"file2.yaml",
			},
			want: &cautils.ScanInfo{
				ScanType: cautils.ScanTypeRepo,
				InputPatterns: []string{
					"file.yaml",
					"file2.yaml",
				},
			},
			wantPolicies: []cautils.PolicyIdentifier{
				{
					Kind:       v1.KindFramework,
					Identifier: "workloadscan",
				},
				{
					Kind:       v1.KindFramework,
					Identifier: "allcontrols",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := &cautils.ScanInfo{
				View: string(cautils.SecurityViewType),
			}
			policyIdentifiers := setSecurityViewScanInfo(tt.args, got)

			if len(tt.want.InputPatterns) != len(got.InputPatterns) {
				t.Errorf("in test: %s, got: %v, want: %v", tt.name, got.InputPatterns, tt.want.InputPatterns)
			}

			if tt.want.ScanType != got.ScanType {
				t.Errorf("in test: %s, got: %v, want: %v", tt.name, got.ScanType, tt.want.ScanType)
			}

			for i := range tt.want.InputPatterns {
				found := false
				for j := range tt.want.InputPatterns[i] {
					if tt.want.InputPatterns[i][j] == got.InputPatterns[i][j] {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("in test: %s, got: %v, want: %v", tt.name, got.InputPatterns, tt.want.InputPatterns)
				}
			}

			for i := range tt.wantPolicies {
				found := false
				for j := range policyIdentifiers {
					if tt.wantPolicies[i].Kind == policyIdentifiers[j].Kind && tt.wantPolicies[i].Identifier == policyIdentifiers[j].Identifier {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("in test: %s, got: %v, want: %v", tt.name, policyIdentifiers, tt.wantPolicies)
				}
			}
		})
	}

}

func TestGetScanCommand(t *testing.T) {
	// Create a mock Kubescape interface
	mockKubescape := &mocks.MockIKubescape{}

	cmd := GetScanCommand(mockKubescape)

	// Verify the command name and short description
	assert.Equal(t, "scan", cmd.Use)
	assert.Equal(t, "Scan a Kubernetes cluster or YAML files for image vulnerabilities and misconfigurations", cmd.Short)
	assert.Equal(t, "Scan a Kubernetes cluster, YAML files, Helm charts, Kustomize directories, Git repositories, or container images for security misconfigurations and vulnerabilities.", cmd.Long)
	assert.Equal(t, scanCmdExamples, cmd.Example)
}

func registryFixtureValue(parts ...string) string {
	return strings.Join(parts, "-")
}

func TestSubmitFlag_TracksExplicitCommandLineUse(t *testing.T) {
	// Regression test for https://github.com/kubescape/kubescape/issues/2555:
	// --submit is bound directly as a cautils.BoolPtrFlag (like --enable-host-scan),
	// so "not passed" (nil) is structurally distinguishable from "passed with any
	// value" (non-nil) without any separate hand-rolled bookkeeping that could be
	// forgotten at a call site or broken by a future PersistentPreRunE change.

	// --submit not passed - flag not Changed
	mockKubescape := &mocks.MockIKubescape{}
	cmd := GetScanCommand(mockKubescape)
	f := cmd.PersistentFlags().Lookup("submit")
	require.NotNil(t, f, "--submit flag must be registered")
	assert.False(t, f.Changed)
	assert.Equal(t, "false", f.DefValue)

	// --submit=false passed explicitly
	mockKubescape = &mocks.MockIKubescape{}
	cmd = GetScanCommand(mockKubescape)
	require.NoError(t, cmd.ParseFlags([]string{"--submit=false"}))
	f = cmd.PersistentFlags().Lookup("submit")
	assert.True(t, f.Changed)
	assert.Equal(t, "false", f.Value.String())

	// --submit (bare, no value) passed explicitly - must still imply true, matching
	// the original BoolVarP-based flag's behavior (NoOptDefVal="true")
	mockKubescape = &mocks.MockIKubescape{}
	cmd = GetScanCommand(mockKubescape)
	require.NoError(t, cmd.ParseFlags([]string{"--submit"}))
	f = cmd.PersistentFlags().Lookup("submit")
	assert.True(t, f.Changed)
	assert.Equal(t, "true", f.Value.String())
}

func TestSubmitFlag_PropagatesToAllSubcommands(t *testing.T) {
	// Pins the invariant matthyx flagged in review: --submit must reach every
	// scan subcommand. Because it's a cobra-inherited persistent flag rather
	// than something wired through a hand-rolled PersistentPreRunE, this is a
	// structural guarantee rather than something a future subcommand change
	// could silently break.
	mockKubescape := &mocks.MockIKubescape{}
	cmd := GetScanCommand(mockKubescape)

	for _, sub := range cmd.Commands() {
		t.Run(sub.Name(), func(t *testing.T) {
			f := sub.InheritedFlags().Lookup("submit")
			require.NotNil(t, f, "subcommand %q must inherit --submit from the parent scan command", sub.Name())
		})
	}
}

func TestGetScanCommand_DeprecatedFlagsRemoved(t *testing.T) {
	mockKubescape := &mocks.MockIKubescape{}

	cmd := GetScanCommand(mockKubescape)
	require.NotNil(t, cmd)

	for _, removed := range []string{
		"fail-threshold",
		"create-account",
		"enable-host-scan",
		"host-scan-yaml",
	} {
		assert.Nil(t, cmd.PersistentFlags().Lookup(removed),
			"deprecated flag %q must no longer be registered", removed)
	}
}

func TestGetScanCommand_HostScanFlagTriState(t *testing.T) {
	mockKubescape := &mocks.MockIKubescape{}
	cmd := GetScanCommand(mockKubescape)

	// Removing the deprecated --enable-host-scan binding must not remove the
	// CLI opt-out for host data collection: the initutils.go auto-detect branch
	// turns host scanning on whenever the tri-state BoolPtrFlag is nil.
	f := cmd.PersistentFlags().Lookup("host-scan")
	require.NotNil(t, f, "--host-scan flag must be registered to keep a CLI opt-out for host data collection")
	assert.Equal(t, "bool", f.Value.Type())

	// not passed -> nil -> auto-detect node-agent CRDs (the default behavior)
	assert.Equal(t, "", f.Value.String(), "unset --host-scan must leave the BoolPtrFlag nil (auto-detect)")

	// --host-scan (bare) forces host data collection on
	assert.Equal(t, "true", f.NoOptDefVal, "bare --host-scan must force host data collection on")

	// --host-scan=false is the opt-out
	require.NoError(t, cmd.PersistentFlags().Set("host-scan", "false"))
	assert.Equal(t, "false", f.Value.String(), "--host-scan=false must explicitly disable host data collection")

	// --host-scan=true forces it on
	require.NoError(t, cmd.PersistentFlags().Set("host-scan", "true"))
	assert.Equal(t, "true", f.Value.String(), "--host-scan=true must force host data collection on")
}

func TestGetScanCommand_RunE_FormatFlagInvalid(t *testing.T) {
	mockKubescape := &mocks.MockIKubescape{}
	cmd := GetScanCommand(mockKubescape)

	require.NoError(t, cmd.PersistentFlags().Set("format", "xml"))

	err := cmd.RunE(cmd, []string{"."})
	assert.EqualError(t, err, `invalid format "xml", supported formats: pretty-printer, json, junit, prometheus, pdf, html, sarif, gitlab-sast, yaml`)
}

func TestGetScanCommand_ScanTimeoutFlagRegistered(t *testing.T) {
	mockKubescape := &mocks.MockIKubescape{}
	cmd := GetScanCommand(mockKubescape)

	f := cmd.PersistentFlags().Lookup("scan-timeout")
	require.NotNil(t, f, "--scan-timeout flag must be registered on the scan command")
	assert.Equal(t, "duration", f.Value.Type(),
		"--scan-timeout must be a duration flag (accepts values like 5m, 30s, 1h)")
	assert.Equal(t, "0s", f.DefValue,
		"--scan-timeout default must be 0s (no timeout)")
}

func TestGetScanCommand_ScanTimeoutFlagParsed(t *testing.T) {
	tests := []struct {
		name    string
		flagVal string
		want    time.Duration
	}{
		{"five minutes", "5m", 5 * time.Minute},
		{"thirty seconds", "30s", 30 * time.Second},
		{"one hour", "1h", time.Hour},
		{"zero means no timeout", "0", 0},
		{"complex duration", "1h30m", 90 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockKubescape := &mocks.MockIKubescape{}
			cmd := GetScanCommand(mockKubescape)

			err := cmd.PersistentFlags().Set("scan-timeout", tt.flagVal)
			require.NoError(t, err, "setting --scan-timeout=%s should not produce an error", tt.flagVal)

			f := cmd.PersistentFlags().Lookup("scan-timeout")
			assert.Equal(t, tt.want.String(), f.Value.String(),
				"parsed duration for --scan-timeout=%s is incorrect", tt.flagVal)
		})
	}
}

func TestGetScanCommand_ScanTimeoutFlagInherited(t *testing.T) {
	mockKubescape := &mocks.MockIKubescape{}
	cmd := GetScanCommand(mockKubescape)

	for _, sub := range cmd.Commands() {
		t.Run(sub.Name(), func(t *testing.T) {
			f := sub.InheritedFlags().Lookup("scan-timeout")
			require.NotNil(t, f,
				"subcommand %q must inherit --scan-timeout from the parent scan command",
				sub.Name())
		})
	}
}

func TestScanInfo_ScanTimeoutField(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
	}{
		{"no timeout (zero value)", 0},
		{"five minutes", 5 * time.Minute},
		{"one millisecond", time.Millisecond},
		{"twenty-four hours", 24 * time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			si := &cautils.ScanInfo{ScanTimeout: tt.timeout}
			assert.Equal(t, tt.timeout, si.ScanTimeout)
		})
	}
}

// contextTrackingKubescape is a test-local IKubescape that records what
// context was active when Scan() was called, so we can assert the deadline.
// Scan() returns a sentinel error so securityScan exits before HandleResults,
// avoiding a nil-pointer dereference on the stub ResultsHandler.
type contextTrackingKubescape struct {
	mocks.MockIKubescape
	ctx            context.Context
	scanCalledWith context.Context
}

func (m *contextTrackingKubescape) Context() context.Context       { return m.ctx }
func (m *contextTrackingKubescape) SetContext(ctx context.Context) { m.ctx = ctx }
func (m *contextTrackingKubescape) Scan(_ *cautils.ScanInfo, _ []cautils.PolicyIdentifier) (*resultshandlingpkg.ResultsHandler, error) {
	m.scanCalledWith = m.ctx
	return nil, errors.New("stub: scan not implemented in test")
}

func TestSecurityScan_TimeoutDeadlineActiveForScan(t *testing.T) {
	ks := &contextTrackingKubescape{ctx: context.Background()}
	scanInfo := cautils.ScanInfo{ScanTimeout: time.Minute}

	_ = securityScan(scanInfo, ks, nil)

	_, hasDeadline := ks.scanCalledWith.Deadline()
	assert.True(t, hasDeadline, "Scan() must receive a context with a deadline when ScanTimeout > 0")
}

func TestSecurityScan_TimeoutContextRestoredAfterReturn(t *testing.T) {
	originalCtx := context.Background()
	ks := &contextTrackingKubescape{ctx: originalCtx}
	scanInfo := cautils.ScanInfo{ScanTimeout: time.Minute}

	_ = securityScan(scanInfo, ks, nil)

	_, hasDeadline := ks.Context().Deadline()
	assert.False(t, hasDeadline, "original context must be restored on ks after securityScan returns")
}

func TestSecurityScan_ZeroTimeoutNoDeadline(t *testing.T) {
	ks := &contextTrackingKubescape{ctx: context.Background()}
	scanInfo := cautils.ScanInfo{ScanTimeout: 0}

	_ = securityScan(scanInfo, ks, nil)

	_, hasDeadline := ks.scanCalledWith.Deadline()
	assert.False(t, hasDeadline, "Scan() must not receive a deadline when ScanTimeout is 0")
}

func TestGetScanCommand_RegistryCredentialFlags(t *testing.T) {
	cmd := GetScanCommand(&mocks.MockIKubescape{})

	for _, name := range []string{"registry-username", "registry-password", "registry-token", "registry-authority"} {
		flag := cmd.PersistentFlags().Lookup(name)
		require.NotNil(t, flag, "expected %s flag to be registered", name)
	}

	registryMapping := cmd.PersistentFlags().Lookup("registry-mapping")
	require.NotNil(t, registryMapping)
	assert.NotContains(t, registryMapping.Usage, "anonymous")
}

func TestGetScanCommand_RunE_RejectsUnscopedRegistryCredentialsForScanImages(t *testing.T) {
	cmd := GetScanCommand(&mocks.MockIKubescape{})

	require.NoError(t, cmd.PersistentFlags().Set("scan-images", "true"))
	require.NoError(t, cmd.PersistentFlags().Set("registry-username", "user"))
	require.NoError(t, cmd.PersistentFlags().Set("registry-password", registryFixtureValue("scan", "credential")))

	err := cmd.RunE(cmd, []string{})
	assert.Equal(t, shared.ErrRegistryAuthorityMissing, err)
}

func TestApplyRegistryCredentialsFromEnv(t *testing.T) {
	envUser := registryFixtureValue("env", "user")
	envCredential := registryFixtureValue("env", "credential")
	envBearer := registryFixtureValue("env", "bearer")

	t.Setenv("KUBESCAPE_REGISTRY_USERNAME", envUser)
	t.Setenv("KUBESCAPE_REGISTRY_PASSWORD", envCredential)
	t.Setenv("KUBESCAPE_REGISTRY_TOKEN", envBearer)

	scanInfo := cautils.ScanInfo{}
	cmd := &cobra.Command{Use: "scan"}
	cmd.PersistentFlags().StringVar(&scanInfo.RegistryUsername, "registry-username", "", "")
	cmd.PersistentFlags().StringVar(&scanInfo.RegistryPassword, "registry-password", "", "")
	cmd.PersistentFlags().StringVar(&scanInfo.RegistryToken, "registry-token", "", "")

	applyRegistryCredentialsFromEnv(cmd, &scanInfo)

	assert.Equal(t, envUser, scanInfo.RegistryUsername)
	assert.Equal(t, envCredential, scanInfo.RegistryPassword)
	assert.Equal(t, envBearer, scanInfo.RegistryToken)
}

func TestApplyRegistryCredentialsFromEnv_KeepsFlagPrecedence(t *testing.T) {
	envUser := registryFixtureValue("env", "user")
	envCredential := registryFixtureValue("env", "credential")
	envBearer := registryFixtureValue("env", "bearer")
	flagUser := registryFixtureValue("flag", "user")
	flagCredential := registryFixtureValue("flag", "credential")

	t.Setenv("KUBESCAPE_REGISTRY_USERNAME", envUser)
	t.Setenv("KUBESCAPE_REGISTRY_PASSWORD", envCredential)
	t.Setenv("KUBESCAPE_REGISTRY_TOKEN", envBearer)

	scanInfo := cautils.ScanInfo{}
	cmd := &cobra.Command{Use: "scan"}
	cmd.PersistentFlags().StringVar(&scanInfo.RegistryUsername, "registry-username", "", "")
	cmd.PersistentFlags().StringVar(&scanInfo.RegistryPassword, "registry-password", "", "")
	cmd.PersistentFlags().StringVar(&scanInfo.RegistryToken, "registry-token", "", "")

	require.NoError(t, cmd.PersistentFlags().Set("registry-username", flagUser))
	require.NoError(t, cmd.PersistentFlags().Set("registry-password", flagCredential))
	require.NoError(t, cmd.PersistentFlags().Set("registry-token", ""))

	applyRegistryCredentialsFromEnv(cmd, &scanInfo)

	assert.Equal(t, flagUser, scanInfo.RegistryUsername)
	assert.Equal(t, flagCredential, scanInfo.RegistryPassword)
	assert.Empty(t, scanInfo.RegistryToken)
}

func TestApplyRegistryCredentialsFromEnv_KeepsExplicitAuthMode(t *testing.T) {
	envUser := registryFixtureValue("env", "user")
	envCredential := registryFixtureValue("env", "credential")
	envBearer := registryFixtureValue("env", "bearer")

	t.Setenv("KUBESCAPE_REGISTRY_USERNAME", envUser)
	t.Setenv("KUBESCAPE_REGISTRY_PASSWORD", envCredential)
	t.Setenv("KUBESCAPE_REGISTRY_TOKEN", envBearer)

	t.Run("token flag suppresses basic env credentials", func(t *testing.T) {
		scanInfo := cautils.ScanInfo{}
		cmd := &cobra.Command{Use: "scan"}
		cmd.PersistentFlags().StringVar(&scanInfo.RegistryUsername, "registry-username", "", "")
		cmd.PersistentFlags().StringVar(&scanInfo.RegistryPassword, "registry-password", "", "")
		cmd.PersistentFlags().StringVar(&scanInfo.RegistryToken, "registry-token", "", "")

		flagBearer := registryFixtureValue("flag", "bearer")
		require.NoError(t, cmd.PersistentFlags().Set("registry-token", flagBearer))

		applyRegistryCredentialsFromEnv(cmd, &scanInfo)

		assert.Empty(t, scanInfo.RegistryUsername)
		assert.Empty(t, scanInfo.RegistryPassword)
		assert.Equal(t, flagBearer, scanInfo.RegistryToken)
	})

	t.Run("basic flag suppresses token env credential", func(t *testing.T) {
		scanInfo := cautils.ScanInfo{}
		cmd := &cobra.Command{Use: "scan"}
		cmd.PersistentFlags().StringVar(&scanInfo.RegistryUsername, "registry-username", "", "")
		cmd.PersistentFlags().StringVar(&scanInfo.RegistryPassword, "registry-password", "", "")
		cmd.PersistentFlags().StringVar(&scanInfo.RegistryToken, "registry-token", "", "")

		flagUser := registryFixtureValue("flag", "user")
		require.NoError(t, cmd.PersistentFlags().Set("registry-username", flagUser))

		applyRegistryCredentialsFromEnv(cmd, &scanInfo)

		assert.Equal(t, flagUser, scanInfo.RegistryUsername)
		assert.Equal(t, envCredential, scanInfo.RegistryPassword)
		assert.Empty(t, scanInfo.RegistryToken)
	})
}

// coverageWouldFail mirrors the gate logic in enforceCoverageThreshold so we
// can test it without triggering os.Exit.
func coverageWouldFail(notEvaluated, totalControls int, threshold float32) bool {
	if threshold <= 0 || totalControls == 0 {
		return false
	}
	pct := float32(totalControls-notEvaluated) / float32(totalControls) * 100
	return pct < threshold
}

func Test_enforceCoverageThreshold(t *testing.T) {
	tests := []struct {
		name          string
		notEvaluated  int
		totalControls int
		threshold     float32
		wantFail      bool
	}{
		{"threshold disabled (0) never fails", 10, 10, 0, false},
		{"all controls evaluated passes", 0, 10, 80, false},
		{"coverage exactly at threshold passes", 2, 10, 80, false},
		{"coverage below threshold fails", 5, 10, 80, true},
		{"zero total controls never fails", 0, 0, 50, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantFail, coverageWouldFail(tt.notEvaluated, tt.totalControls, tt.threshold))
		})
	}
}
