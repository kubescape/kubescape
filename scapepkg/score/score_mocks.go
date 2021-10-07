package score

import (
	"encoding/json"
	"os"
	"strings"

	k8sinterface "github.com/armosec/kubescape/cautils/k8sinterface"
	"github.com/armosec/kubescape/cautils/opapolicy"
)

func loadResourcesMock() []map[string]interface{} {
	resources := make([]map[string]interface{}, 0)

	dat, err := os.ReadFile("resourcemocks.json")

	if err != nil {
		return resources
	}
	if err := json.Unmarshal(dat, &resources); err != nil {
		return resources
	}

	return resources
}

func getResouceByType(desiredType string) map[string]interface{} {
	rsrcs := loadResourcesMock()
	if rsrcs == nil {
		return nil
	}
	for _, v := range rsrcs {
		wl := k8sinterface.NewWorkloadObj(v)
		if wl != nil {
			if strings.ToLower(wl.GetKind()) == desiredType {
				return v
			}
			continue

		} else {
			for k := range v {
				if k == desiredType {
					return v
				}
			}
		}
	}
	return nil
}

func loadFrameworkMock() *opapolicy.FrameworkReport {
	report := &opapolicy.FrameworkReport{}

	dat, err := os.ReadFile("frameworkmock.json")

	if err != nil {
		return report
	}
	if err := json.Unmarshal(dat, &report); err != nil {
		return report
	}

	return report
}
func getMITREFrameworkResultMock() []opapolicy.FrameworkReport {
	l := make([]opapolicy.FrameworkReport, 0)
	report := loadFrameworkMock()
	resources := loadResourcesMock()
	if report != nil && resources != nil {

		report.ControlReports[0].RuleReports[0].ListInputResources = resources
		l = append(l, *report)

	}

	return l
}
