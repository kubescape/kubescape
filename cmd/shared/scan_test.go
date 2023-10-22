package shared

import (
	"context"
	"os"
	"reflect"
	"testing"

	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling/apis"
)

type spyLogMessage struct {
	Message string
	Details map[string]string
}

type spyLogger struct {
	setItems []spyLogMessage
}

func (l *spyLogger) Error(msg string, details ...helpers.IDetails)       {}
func (l *spyLogger) Success(msg string, details ...helpers.IDetails)     {}
func (l *spyLogger) Warning(msg string, details ...helpers.IDetails)     {}
func (l *spyLogger) Info(msg string, details ...helpers.IDetails)        {}
func (l *spyLogger) Debug(msg string, details ...helpers.IDetails)       {}
func (l *spyLogger) SetLevel(level string) error                         { return nil }
func (l *spyLogger) GetLevel() string                                    { return "" }
func (l *spyLogger) SetWriter(w *os.File)                                {}
func (l *spyLogger) GetWriter() *os.File                                 { return &os.File{} }
func (l *spyLogger) LoggerName() string                                  { return "" }
func (l *spyLogger) Ctx(_ context.Context) helpers.ILogger               { return l }
func (l *spyLogger) Start(msg string, details ...helpers.IDetails)       {}
func (l *spyLogger) StopSuccess(msg string, details ...helpers.IDetails) {}
func (l *spyLogger) StopError(msg string, details ...helpers.IDetails)   {}

func (l *spyLogger) Fatal(msg string, details ...helpers.IDetails) {
	firstDetail := details[0]
	detailsMap := map[string]string{firstDetail.Key(): firstDetail.Value().(string)}

	newMsg := spyLogMessage{msg, detailsMap}
	l.setItems = append(l.setItems, newMsg)
}

func (l *spyLogger) GetSpiedItems() []spyLogMessage {
	return l.setItems
}

func TestTerminateOnExceedingSeverity(t *testing.T) {
	expectedMessage := "result exceeds severity threshold"
	expectedKey := "Set severity threshold"

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

				TerminateOnExceedingSeverity(scanInfo, tc.Logger)

				got := tc.Logger.GetSpiedItems()
				if !reflect.DeepEqual(got, want) {
					t.Errorf("got: %v, want: %v", got, want)
				}
			},
		)
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
