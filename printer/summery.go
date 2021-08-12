package printer

import "fmt"

type Summery map[string]ControlSummery

func NewSummery() Summery {
	return make(map[string]ControlSummery)
}

type ControlSummery struct {
	TotalResources  int
	TotalFailed     int
	Description     string
	WorkloadSummery map[string][]WorkloadSummery
}

type WorkloadSummery struct {
	Kind      string
	Name      string
	Namespace string
	Group     string
}

func (summery *Summery) SetWorkloadSummery(c string, ws map[string][]WorkloadSummery) {
	s := (*summery)[c]
	s.WorkloadSummery = ws
}

func (summery *Summery) SetTotalResources(c string, t int) {
	s := (*summery)[c]
	s.TotalResources = t
}

func (summery *Summery) SetTotalFailed(c string, t int) {
	s := (*summery)[c]
	s.TotalFailed = t
}

func (summery *Summery) SetDescription(c string, d string) {
	s := (*summery)[c]
	s.Description = d
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
