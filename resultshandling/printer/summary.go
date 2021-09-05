package printer

import (
	"fmt"

	"github.com/armosec/kubescape/cautils/armotypes"
)

type Summary map[string]ControlSummary

func NewSummary() Summary {
	return make(map[string]ControlSummary)
}

type ControlSummary struct {
	TotalResources  int
	TotalFailed     int
	TotalWarnign    int
	Description     string
	Remediation     string
	ListInputKinds  []string
	WorkloadSummary map[string][]WorkloadSummary // <namespace>:[<WorkloadSummary>]
}

type WorkloadSummary struct {
	Kind      string
	Name      string
	Namespace string
	Group     string
	Exception *armotypes.PostureExceptionPolicy
}

func (controlSummary *ControlSummary) ToSlice() []string {
	s := []string{}
	s = append(s, fmt.Sprintf("%d", controlSummary.TotalFailed))
	s = append(s, fmt.Sprintf("%d", controlSummary.TotalWarnign))
	s = append(s, fmt.Sprintf("%d", controlSummary.TotalResources))
	return s
}

func (workloadSummary *WorkloadSummary) ToString() string {
	return fmt.Sprintf("/%s/%s/%s/%s", workloadSummary.Group, workloadSummary.Namespace, workloadSummary.Kind, workloadSummary.Name)
}
