package scan

import (
	"context"

	"github.com/kubescape/go-logger/helpers"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"

	"os"
	"reflect"
	"testing"
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
			Error:            ErrUnknownSeverity,
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

func (l *spyLogger) Error(msg string, details ...helpers.IDetails)   {}
func (l *spyLogger) Success(msg string, details ...helpers.IDetails) {}
func (l *spyLogger) Warning(msg string, details ...helpers.IDetails) {}
func (l *spyLogger) Info(msg string, details ...helpers.IDetails)    {}
func (l *spyLogger) Debug(msg string, details ...helpers.IDetails)   {}
func (l *spyLogger) SetLevel(level string) error                     { return nil }
func (l *spyLogger) GetLevel() string                                { return "" }
func (l *spyLogger) SetWriter(w *os.File)                            {}
func (l *spyLogger) GetWriter() *os.File                             { return &os.File{} }
func (l *spyLogger) LoggerName() string                              { return "" }
func (l *spyLogger) Ctx(_ context.Context) helpers.ILogger           { return l }

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
	expectedMessage := "result exceeds severity threshold"
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
