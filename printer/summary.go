package printer

import (
	"fmt"
)

type Summary map[string]ControlSummary

func NewSummary() Summary {
	return make(map[string]ControlSummary)
}

type ControlSummary struct {
	TotalResources  int
	TotalFailed     int
	Description     string
	Remediation     string
	WorkloadSummary map[string][]WorkloadSummary // <namespace>:[<WorkloadSummary>]
}

type WorkloadSummary struct {
	Kind      string
	Name      string
	Namespace string
	Group     string
}

func (controlSummary *ControlSummary) ToSlice() []string {
	s := []string{}
	s = append(s, fmt.Sprintf("%d", controlSummary.TotalFailed))
	s = append(s, fmt.Sprintf("%d", controlSummary.TotalResources))
	return s
}

func (workloadSummary *WorkloadSummary) ToString() string {
	return fmt.Sprintf("/%s/%s/%s/%s", workloadSummary.Group, workloadSummary.Namespace, workloadSummary.Kind, workloadSummary.Name)
}
