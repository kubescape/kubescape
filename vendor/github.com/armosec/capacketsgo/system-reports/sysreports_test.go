package systemReport

import (
	"encoding/json"
	"strconv"
	"sync"
	"testing"

	"github.com/armosec/capacketsgo/system-reports/datastructures"
	"github.com/armosec/capacketsgo/system-reports/utilities"
	"github.com/golang/glog"
)

func TestBaseReportStructure(t *testing.T) {
	a := datastructures.BaseReport{Reporter: "unit-test", Target: "unit-test-framework", JobID: "id", ActionID: "id2"}
	timestamp := a.Timestamp

	a.Send()
	if timestamp == a.Timestamp {
		t.Errorf("Expecting different timestamp when sending a notification, received %v", a)
	}

}

func TestFirstBaseReportStructure(t *testing.T) {
	a := datastructures.BaseReport{Reporter: "unit-test", Target: "unit-test-framework"}
	_, id, _ := a.Send()
	if id != a.JobID {
		t.Errorf("Expecting to have proccessID generated from 1st report, received %v", a)
	}

}

func TestJobsAnnotation(t *testing.T) {
	a := datastructures.JobsAnnotations{CurrJobID: "test-job", LastActionID: "1"}

	marshal, err := json.Marshal(a)
	if err != nil {
		t.Errorf("unable to stringify job annotation: %v", a)
	}

	jobid, obj, err := utilities.GetJobIDByContext(marshal, "test")
	if err != nil {
		t.Errorf("unable to parhe json job annotation: %v", a)
	}

	if jobid != "test-job" || a.CurrJobID != obj.CurrJobID || a.LastActionID != obj.LastActionID || a.ParentJobID != obj.ParentJobID {
		t.Error("unable to parse job annotation correctly")
	}

}

func TestBaseReportNextActionID(t *testing.T) {
	a := datastructures.BaseReport{Reporter: "unit-test", Target: "unit-test-framework", Status: "started", JobID: "processid1", ActionID: "1"}
	a.Send()
	a.NextActionID()
	a.Send()
	a.NextActionID()
	a.Send()
	a.NextActionID()

	if a.ActionID != "4" {
		t.Errorf("NextActionID had unexpected behaviour %v", a)
	}
}

func TestBaseReportTestConcurrentErrorAdding(t *testing.T) {
	a := &datastructures.BaseReport{Reporter: "unit-test", Target: "unit-test-framework", Status: "started", JobID: "processid1", ActionID: "1"}
	var wg sync.WaitGroup
	for j := 0; j < 10; j++ {

		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func(i int, wg *sync.WaitGroup) {
				defer wg.Done()
				s := strconv.Itoa(i)
				glog.Errorf("%s", s)
				a.AddError(s)
			}(i, &wg)
		}
		wg.Wait()

		if len(a.Errors) != 4 {
			t.Errorf("an inconsistency error occured at round %d, expected 4 errors and got %v", j, a)
		}
		a.Errors = nil

	}
}

//integration test- works
// func TestImmutableBaseReport(t *testing.T) {
// 	jobId := ""
// 	// target, reporter, actionID, action, status string, jobID *string, err error
// 	utilities.SendImuttableReport("wlid://unit-test", "unit-test", "1", "testing", "starting", &jobId, fmt.Errorf("severe error"))
// 	// if len(jobId) == 0 {

// 	t.Errorf("%v", jobId)
// 	// }
//}
