package datastructures

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang/glog"
)

var MAX_RETRIES int = 3

func (report *BaseReport) InitMutex() {
	report.mutex = sync.Mutex{}
}

func (report *BaseReport) NextActionID() {
	report.ActionIDN++
	report.ActionID = report.GetNextActionId()
}
func (report *BaseReport) SimpleReportAnnotations(setParent bool, setCurrent bool) (string, string) {

	nextactionID := report.GetNextActionId()

	jobs := JobsAnnotations{LastActionID: nextactionID}
	if setParent {
		jobs.ParentJobID = report.JobID
	}
	if setCurrent {
		jobs.CurrJobID = report.JobID
	}
	jsonAsString, _ := json.Marshal(jobs)
	return string(jsonAsString), nextactionID
	//ok
}

func (report *BaseReport) GetNextActionId() string {
	return strconv.Itoa(report.ActionIDN)
}

func (report *BaseReport) AddError(er string) {
	report.mutex.Lock()
	defer report.mutex.Unlock()
	if report.Errors == nil {
		report.Errors = make([]string, 0)
	}
	report.Errors = append(report.Errors, er)
}

func (report *BaseReport) SendAsRoutine(collector []string, progressNext bool) {
	report.mutex.Lock()
	go func() {
		defer report.mutex.Unlock()
		status, _, _ := report.Send()
		if status < 200 || status >= 300 {
			// TODO handle error
		}
		if progressNext {
			report.NextActionID()
		}
	}()
}
func (report *BaseReport) GetReportID() string {
	return fmt.Sprintf("%s::%s::%s (verbose:  %s::%s)", report.Target, report.JobID, report.ActionID, report.ParentAction, report.ActionName)
}

// Send - send http request. returns-> http status code, return message (jobID/OK), http/go error
func (report *BaseReport) Send() (int, string, error) {

	url := os.Getenv("CA_EVENT_RECEIVER_HTTP")

	if len(url) == 0 {
		url = os.Getenv("CA_ARMO_EVENT_URL") // Deprecated
		if len(url) == 0 {
			glog.Errorf("%s - Error: CA_EVENT_RECEIVER_HTTP is missing", report.GetReportID())
			return 0, "", nil
		}
	}
	url = url + SysreportEndpoint
	report.Timestamp = time.Now()
	if report.ActionID == "" {
		report.ActionID = "1"
		report.ActionIDN = 1
	}
	reqBody, err := json.Marshal(report)

	if err != nil {
		glog.Errorf("%s - Failed to marshall report object", report.GetReportID())
		return 500, "Couldn't marshall report object", err
	}
	var resp *http.Response

	for i := 0; i < MAX_RETRIES; i++ {
		resp, err = http.Post(url, "application/json", bytes.NewBuffer(reqBody))
		if err == nil {
			break
		}
		e := fmt.Errorf("attempt #%d %s - Failed posting report. Url: '%s', reason: '%s' report: '%s' ", i, report.GetReportID(), url, err.Error(), string(reqBody))
		glog.Error(e)

		if i == MAX_RETRIES-1 {
			return 500, e.Error(), err
		}

	}
	// TODO - test retry

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	bodyAsStr := "body could not be fetched"
	if err == nil {
		bodyAsStr = string(body)
	}

	//first successful report gets it's jobID/proccessID
	if len(report.JobID) == 0 && bodyAsStr != "ok" && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		report.JobID = bodyAsStr
		glog.Infof("Generated jobID: '%s'", report.JobID)
	}
	return resp.StatusCode, bodyAsStr, nil
}

// ======================================== SEND WRAPPER =======================================

// SendError - wrap AddError
func (report *BaseReport) SendError(err error, sendReport bool, initErrors bool) {
	report.mutex.Lock() // +

	if report.Errors == nil {
		report.Errors = make([]string, 0)
	}
	if err != nil {
		e := fmt.Sprintf("Action: %s, Error: %s", report.ActionName, err.Error())
		report.Errors = append(report.Errors, e)
	}
	report.Status = JobFailed // TODO - Add flag?
	report.mutex.Unlock()     // -
	if sendReport {
		report.SendAsRoutine([]string{}, true)
	}
	if sendReport && initErrors {
		report.mutex.Lock() // +
		report.Errors = make([]string, 0)
		report.mutex.Unlock() // -
	}
}

func (report *BaseReport) SendAction(actionName string, sendReport bool) {
	report.SetActionName(actionName)
	if sendReport {
		report.SendAsRoutine([]string{}, true)
	}
}

func (report *BaseReport) SendStatus(status string, sendReport bool) {
	report.SetStatus(status)
	if sendReport {
		report.SendAsRoutine([]string{}, true)
	}
}

// ============================================ SET ============================================

func (report *BaseReport) SetReporter(reporter string) {
	report.mutex.Lock()
	defer report.mutex.Unlock()
	report.Reporter = strings.Title(reporter)
}
func (report *BaseReport) SetStatus(status string) {
	report.mutex.Lock()
	defer report.mutex.Unlock()
	report.Status = status
}

func (report *BaseReport) SetActionName(actionName string) {
	report.mutex.Lock()
	defer report.mutex.Unlock()
	report.ActionName = strings.Title(actionName)
	report.Status = JobStarted
}

func (report *BaseReport) SetDetails(details string) {
	report.mutex.Lock()
	defer report.mutex.Unlock()
	report.Details = details
}

func (report *BaseReport) SetTarget(target string) {
	report.mutex.Lock()
	defer report.mutex.Unlock()
	report.Target = target
}

func (report *BaseReport) SetActionID(actionID string) {
	report.mutex.Lock()
	defer report.mutex.Unlock()
	report.ActionID = actionID
}

func (report *BaseReport) SetJobID(jobID string) {
	report.mutex.Lock()
	defer report.mutex.Unlock()
	report.JobID = jobID
}

func (report *BaseReport) SetParentAction(parentAction string) {
	report.mutex.Lock()
	defer report.mutex.Unlock()
	report.ParentAction = parentAction
}

func (report *BaseReport) SetCustomerGUID(customerGUID string) {
	report.mutex.Lock()
	defer report.mutex.Unlock()
	report.CustomerGUID = customerGUID
}

func (report *BaseReport) SetActionIDN(actionIDN int) {
	report.mutex.Lock()
	defer report.mutex.Unlock()
	report.ActionIDN = actionIDN
	report.ActionID = strconv.Itoa(report.ActionIDN)
}

func (report *BaseReport) SetTimestamp(timestamp time.Time) {
	report.mutex.Lock()
	defer report.mutex.Unlock()
	report.Timestamp = timestamp
}

// ============================================ GET ============================================
func (report *BaseReport) GetActionName() string {
	return report.ActionName
}

func (report *BaseReport) GetStatus() string {
	return report.Status
}

func (report *BaseReport) GetErrorList() []string {
	return report.Errors
}

func (report *BaseReport) GetTarget() string {
	return report.Target
}

func (report *BaseReport) GetReporter() string {
	return report.Reporter
}

func (report *BaseReport) GetActionID() string {
	return report.ActionID
}

func (report *BaseReport) GetJobID() string {
	return report.JobID
}

func (report *BaseReport) GetParentAction() string {
	return report.ParentAction
}

func (report *BaseReport) GetCustomerGUID() string {
	return report.CustomerGUID
}

func (report *BaseReport) GetActionIDN() int {
	return report.ActionIDN
}

func (report *BaseReport) GetTimestamp() time.Time {
	return report.Timestamp
}

func (report *BaseReport) GetDetails() string {
	return report.Details
}
