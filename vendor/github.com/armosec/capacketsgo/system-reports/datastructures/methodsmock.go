package datastructures

import (
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"
)

func (reportMock *BaseReportMock) InitMutex() {
	reportMock.mutex = sync.Mutex{}
}

func (reportMock *BaseReportMock) NextActionID() {
	reportMock.ActionIDN++
	reportMock.ActionID = reportMock.GetNextActionId()
}
func (reportMock *BaseReportMock) SimpleReportAnnotations(setParent bool, setCurrent bool) (string, string) {

	nextactionID := reportMock.GetNextActionId()

	jobs := JobsAnnotations{LastActionID: nextactionID}
	if setParent {
		jobs.ParentJobID = reportMock.JobID
	}
	if setCurrent {
		jobs.CurrJobID = reportMock.JobID
	}
	jsonAsString, _ := json.Marshal(jobs)
	return string(jsonAsString), nextactionID
}

func (reportMock *BaseReportMock) GetNextActionId() string {
	return strconv.Itoa(reportMock.ActionIDN)
}

func (reportMock *BaseReportMock) AddError(er string) {
	reportMock.mutex.Lock()
	defer reportMock.mutex.Unlock()
	if reportMock.Errors == nil {
		reportMock.Errors = make([]string, 0)
	}
	reportMock.Errors = append(reportMock.Errors, er)
}
func (reportMock *BaseReportMock) SendAsRoutine(collector []string, progressNext bool) {
	go func() {

		reportMock.mutex.Lock()
		defer reportMock.mutex.Unlock()
		status, _, _ := reportMock.Send()
		if status < 200 || status >= 300 {
			//handle error
		}
		if progressNext {
			reportMock.NextActionID()
		}
	}()
}
func (reportMock *BaseReportMock) GetReportID() string {
	return fmt.Sprintf("%s::%s::%s (verbose:  %s::%s)", reportMock.Target, reportMock.JobID, reportMock.ActionID, reportMock.ParentAction, reportMock.ActionName)
}

func (reportMock *BaseReportMock) Send() (int, string, error) {
	return 200, "", nil
}

// ======================================== SEND WRAPPER =======================================

// SendError - wrap AddError
func (reportMock *BaseReportMock) SendError(err error, sendReport bool, initErrors bool) {
	reportMock.AddError(err.Error())
}

func (reportMock *BaseReportMock) SendAction(actionName string, sendReport bool) {
	reportMock.SetActionName(actionName)
}

func (reportMock *BaseReportMock) SendStatus(status string, sendReport bool) {
	reportMock.SetStatus(status)
}

// ============================================ SET ============================================
func (reportMock *BaseReportMock) SetReporter(reporter string) {
	reportMock.Reporter = reporter
}

func (reportMock *BaseReportMock) SetStatus(status string) {
	reportMock.Status = status
}

func (reportMock *BaseReportMock) SetActionName(actionName string) {
	reportMock.ActionName = actionName
}

func (reportMock *BaseReportMock) SetActionID(actionID string) {
	reportMock.ActionID = actionID
}

func (reportMock *BaseReportMock) SetJobID(jobID string) {
	reportMock.JobID = jobID
}

func (reportMock *BaseReportMock) SetParentAction(parentAction string) {
	reportMock.ParentAction = parentAction
}

func (reportMock *BaseReportMock) SetCustomerGUID(customerGUID string) {
	reportMock.CustomerGUID = customerGUID
}

func (reportMock *BaseReportMock) SetActionIDN(actionIDN int) {
	reportMock.ActionIDN = actionIDN
}

func (reportMock *BaseReportMock) SetTimestamp(timestamp time.Time) {
	reportMock.Timestamp = timestamp
}

func (reportMock *BaseReportMock) SetTarget(target string) {
	reportMock.Target = target
}

// ============================================ GET ============================================
func (reportMock *BaseReportMock) GetReporter() string {
	return reportMock.Reporter
}
func (reportMock *BaseReportMock) GetActionName() string {
	return reportMock.ActionName
}

func (reportMock *BaseReportMock) GetStatus() string {
	return reportMock.Status
}

func (reportMock *BaseReportMock) GetErrorList() []string {
	return reportMock.Errors
}

func (reportMock *BaseReportMock) GetActionID() string {
	return reportMock.ActionID
}

func (reportMock *BaseReportMock) GetJobID() string {
	return reportMock.JobID
}

func (reportMock *BaseReportMock) GetParentAction() string {
	return reportMock.ParentAction
}

func (reportMock *BaseReportMock) GetCustomerGUID() string {
	return reportMock.CustomerGUID
}

func (reportMock *BaseReportMock) GetActionIDN() int {
	return reportMock.ActionIDN
}

func (reportMock *BaseReportMock) GetTimestamp() time.Time {
	return reportMock.Timestamp
}

func (reportMock *BaseReportMock) GetTarget() string {
	return reportMock.Target
}
