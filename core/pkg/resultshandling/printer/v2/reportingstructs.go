package printer

import (
	"github.com/kubescape/k8s-interface/workloadinterface"
)

type ResourceTableView []ResourceResult

type ResourceResult struct {
	Resource       workloadinterface.IMetadata
	ControlsResult []ResourceControlResult
}

type ResourceControlResult struct {
	Severity    string
	Name        string
	ID          string
	URL         string
	FailedPaths []string
}
