package printer

import (
	"fmt"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/k8s-interface/workloadinterface"
)

type Summary map[string]ControlSummary

func NewSummary() Summary {
	return make(map[string]ControlSummary)
}

type ControlSummary struct {
	TotalResources    int
	TotalFailed       int
	TotalWarning      int
	Description       string
	Remediation       string
	ListInputKinds    []string
	FailedWorkloads   map[string][]WorkloadSummary // <namespace>:[<WorkloadSummary>]
	ExcludedWorkloads map[string][]WorkloadSummary // <namespace>:[<WorkloadSummary>]
}

type WorkloadSummary struct {
	FailedWorkload workloadinterface.IMetadata
	Exception      *armotypes.PostureExceptionPolicy
}

func (controlSummary *ControlSummary) ToSlice() []string {
	s := []string{}
	s = append(s, fmt.Sprintf("%d", controlSummary.TotalFailed))
	s = append(s, fmt.Sprintf("%d", controlSummary.TotalWarning))
	s = append(s, fmt.Sprintf("%d", controlSummary.TotalResources))
	return s
}

func (workloadSummary *WorkloadSummary) ToString() string {
	return fmt.Sprintf("/%s/%s/%s/%s", workloadSummary.FailedWorkload.GetApiVersion(), workloadSummary.FailedWorkload.GetNamespace(), workloadSummary.FailedWorkload.GetKind(), workloadSummary.FailedWorkload.GetName())
}

func workloadSummaryFailed(workloadSummary *WorkloadSummary) bool {
	return workloadSummary.Exception == nil
}

func workloadSummaryExclude(workloadSummary *WorkloadSummary) bool {
	return workloadSummary.Exception != nil && workloadSummary.Exception.IsAlertOnly()
}
