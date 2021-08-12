// represent a basic report
package datastructures

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"
)

const (
	SysreportEndpoint = "/k8s/sysreport"
	// //WT related
	// WtPreConfigured = "wt preconfigured"
	// wtUpdateStart   = "wt update started"
)

// JobsAnnotations job annotation
type JobsAnnotations struct {
	/*jobid: context   eg. if a certain job has multiple stages
	  eg. attach namespace>attach wlid in ns
	  so obj when pod is catched should look like:
	  {
		  jobID#1: {
			"attach namespace"
		  }
	  }
	  - SHOULD BE RETHINK
	*/
	// JobIDsContex map[string]string `json:"jobIDsContex,omitempty"`
	CurrJobID    string `json:"jobID"`       //simplest case (for now till we have a better idea)
	ParentJobID  string `json:"parentJobID"` //simplest case (for now till we have a better idea)
	LastActionID string `json:"actionID"`    //simplest case (for now till we have a better idea) used to pass as defining ordering between multiple components
}

//BaseReport : represents the basic reports from various actions eg. attach and so on
//
// ("reporter": "auditlog processor", //the name of your k8s component
//  "target": "<scope> auditlogs", // eg. if you know its cluster & ns you can say: hipstershop/dev auditlogs
//  "status":  <use constants defined above eg. JobStarted>
//  "action": "<the action itself- eg. fetching logs from s3",
//  "errors": <fill if u encountered any>
//  "actionID" & "actionIDN" - numerical representation - eg if it's the first step then it should be 1, it also allow "forks" to happen
// 	"jobID": event reciever will fill that for you
// 	"parentAction": used like if you have like autoattach right? namespaces is the parent job but every wl up has attach but it's parent is the autoattach task
// 	"timestamp": <s.e>
// 	"customerGUID": s.e
// }

// Statuses type
type StatusType string

const (
	JobSuccess string = "success"
	JobFailed  string = "failure"
	JobStarted string = "started"
	JobDone    string = "done"
)

type BaseReport struct {
	CustomerGUID string     `json:"customerGUID"` // customerGUID as declared in environment
	Reporter     string     `json:"reporter"`     // webhook, webscoket, other possible components
	Target       string     `json:"target"`       // wlid, cluster,etc. - which component this event is applicable on
	Status       string     `json:"status"`       // Action scope: Before action use "started", after action use "failure/success". Reporter scope: Before action use "started", after action use "done".
	ActionName   string     `json:"action"`       // Stage action. short description of the action to-be-done. When definding an action
	Errors       []string   `json:"errors,omitempty"`
	ActionID     string     `json:"actionID"`               // Stage counter of the E2E process. initialize at 1. The number is increased when sending job report
	ActionIDN    int        `json:"numSeq"`                 // The ActionID in number presentation
	JobID        string     `json:"jobID"`                  // UID received from the eventReceiver after first report (the initializing is part of the first report)
	ParentAction string     `json:"parentAction,omitempty"` // Parent JobID
	Details      string     `json:"details,omitempty"`      // Parent JobID
	Timestamp    time.Time  `json:"timestamp"`              //
	mutex        sync.Mutex `json:"-"`                      // ignore
	// Status       StatusType `json:"status"`   //it's status
}

//
// ("reporter": "auditlog processor", //the name of your k8s component
//  "target": "<scope> auditlogs", // eg. if you know its cluster & ns you can say: hipstershop/dev auditlogs
//  "status":  <use constants defined above eg. JobStarted>
//  "action": "<the action itself- eg. fetching logs from s3",
//  "errors": <fill if u encountered any>
//  "actionID" & "actionIDN" - numerical representation - eg if it's the first step then it should be 1, it also allow "forks" to happen
// 	"jobID": event reciever will fill that for you
// 	"parentAction": used like if you have like autoattach right? namespaces is the parent job but every wl up has attach but it's parent is the autoattach task
// 	"timestamp": <s.e>
// 	"customerGUID": s.e
// }

// NewBaseReport return pointer to new BaseReport obj
func NewBaseReport(customerGUID, reporter string) *BaseReport {
	return &BaseReport{
		CustomerGUID: customerGUID,
		Reporter:     reporter,
		Status:       JobStarted,
		ActionName:   fmt.Sprintf("Starting %s", reporter),
		ActionID:     "1",
		ActionIDN:    1,
	}
}

// IReporter reporter interface
type IReporter interface {
	// createReport() BaseReport
	Send() (int, string, error) //send logic is here
	GetReportID() string
	AddError(string)
	GetNextActionId() string //get
	NextActionID()
	SimpleReportAnnotations(bool, bool) (string, string)
	SendAsRoutine([]string, bool) //goroutine wrapper

	// set methods
	SendAction(string, bool)
	SendError(error, bool, bool)
	SendStatus(string, bool)

	// set methods
	SetReporter(string)
	SetStatus(string)
	SetActionName(string)
	SetTarget(string)
	SetActionID(string)
	SetJobID(string)
	SetParentAction(string)
	SetTimestamp(time.Time)
	SetActionIDN(int)
	SetCustomerGUID(string)
	SetDetails(string)

	// get methods
	GetReporter() string
	GetStatus() string
	GetActionName() string
	GetTarget() string
	GetErrorList() []string
	GetActionID() string
	GetJobID() string
	GetParentAction() string
	GetTimestamp() time.Time
	GetActionIDN() int
	GetCustomerGUID() string
	GetDetails() string
}

// IsEqual are two IReporter objects equal
func IsEqual(lhs, rhs IReporter) bool {
	if strings.Compare(lhs.GetJobID(), rhs.GetJobID()) != 0 ||
		strings.Compare(lhs.GetStatus(), rhs.GetStatus()) != 0 ||
		strings.Compare(lhs.GetReporter(), rhs.GetReporter()) != 0 ||
		strings.Compare(lhs.GetTarget(), rhs.GetTarget()) != 0 ||
		strings.Compare(lhs.GetActionID(), rhs.GetActionID()) != 0 ||
		strings.Compare(lhs.GetActionName(), rhs.GetActionName()) != 0 ||
		strings.Compare(lhs.GetParentAction(), rhs.GetParentAction()) != 0 ||
		lhs.GetActionIDN() != rhs.GetActionIDN() ||

		lhs.GetTimestamp().Unix() != rhs.GetTimestamp().Unix() ||
		!reflect.DeepEqual(rhs.GetErrorList(), lhs.GetErrorList()) {
		return false
	}

	return true
}
