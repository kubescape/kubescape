package printer

import (
	"fmt"
)

type Summery map[string]ControlSummery

func NewSummery() Summery {
	return make(map[string]ControlSummery)
}

type ControlSummery struct {
	TotalResources  int
	TotalFailed     int
	Description     string
	Remediation     string
	WorkloadSummery map[string][]WorkloadSummery // <namespace>:[<WorkloadSummery>]
}

type WorkloadSummery struct {
	Kind      string
	Name      string
	Namespace string
	Group     string
}

func (controlSummery *ControlSummery) ToSlice() []string {
	s := []string{}
	s = append(s, fmt.Sprintf("%d", controlSummery.TotalFailed))
	s = append(s, fmt.Sprintf("%d", controlSummery.TotalResources))
	return s
}

func (workloadSummery *WorkloadSummery) ToString() string {
	return fmt.Sprintf("/%s/%s/%s/%s", workloadSummery.Group, workloadSummery.Namespace, workloadSummery.Kind, workloadSummery.Name)
}
