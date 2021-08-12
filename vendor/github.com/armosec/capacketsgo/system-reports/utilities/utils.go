package utilities

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/armosec/capacketsgo/armotypes"
	"github.com/armosec/capacketsgo/system-reports/datastructures"
	"github.com/golang/glog"
)

var (
	EmptyString = []string{}
)

//TODO
//takes annotation and return the jobID, annotationObject, err
func GetJobIDByContext(jobs []byte, context string) (string, datastructures.JobsAnnotations, error) {

	var jobject datastructures.JobsAnnotations
	err := json.Unmarshal(jobs, &jobject)

	return jobject.CurrJobID, jobject, err
}

func ProcessAnnotations(reporter datastructures.IReporter, ijobAnot interface{}, hasAnnotations bool) {
	if hasAnnotations {
		glog.Infof("has job annotation %s", ijobAnot)
		tmpstr := fmt.Sprintf("%s", ijobAnot)
		_, jobAnnotObj, jerr := GetJobIDByContext([]byte(tmpstr), "attach")
		if jerr == nil {
			if len(jobAnnotObj.CurrJobID) > 0 {
				reporter.SetJobID(jobAnnotObj.CurrJobID)
			}
			glog.Infof("job annotations object: %v", jobAnnotObj)

			reporter.SetParentAction(jobAnnotObj.ParentJobID)
			reporter.SetActionID(jobAnnotObj.LastActionID)
			actionID, _ := strconv.Atoi(reporter.GetActionID())
			reporter.SetActionIDN(actionID)
		}

	} else {
		glog.Errorf("no job annotation")
	}
}

//incase you want to send it all and just manage jobID, actionID yourself (no locking downtimes)
func SendImuttableReport(target, reporter, actionID, action, status string, jobID *string, err error) {
	// go func(jobID *string) {

	lhs := datastructures.BaseReport{Reporter: reporter, ActionName: action, Target: target, JobID: *jobID, ActionID: actionID, Status: status}
	lhs.ActionIDN, _ = strconv.Atoi(actionID)
	if err != nil {
		lhs.AddError(err.Error())
		glog.Error(err.Error())
	}
	_, *jobID, _ = lhs.Send()

	glog.Infof("sent sys-report: %v", lhs)

	// }(jobID)

}

func InitReporter(customerGUID, reporterName, actionName, wlid string, designator *armotypes.PortalDesignator) *datastructures.BaseReport {
	reporter := datastructures.NewBaseReport(customerGUID, reporterName)
	if actionName != "" {
		reporter.SetActionName(actionName)
	}
	if wlid != "" {
		reporter.SetTarget(wlid)
	} else if designator != nil {
		reporter.SetTarget(GetTargetFromDesignator(designator))
	}
	reporter.SendAsRoutine(EmptyString, true)
	return reporter
}

func GetTargetFromDesignator(designator *armotypes.PortalDesignator) string {
	switch designator.DesignatorType {
	case armotypes.DesignatorWlid:
		return designator.WLID
	case armotypes.DesignatorWildWlid:
		return designator.WildWLID
	case armotypes.DesignatorAttributes:
		if designator.Attributes != nil {
			return convertMapToString(designator.Attributes)
		}
	}
	return "Unknown target"
}

func convertMapToString(smap map[string]string) string {
	str := ""
	for i := range smap {
		str += fmt.Sprintf("%s=%s;", i, smap[i])
	}
	return str
}
