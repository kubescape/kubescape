package cliinterfaces

import (
	"github.com/armosec/k8s-interface/workloadinterface"
	"github.com/armosec/kubescape/v2/core/cautils"
	"github.com/armosec/kubescape/v2/core/pkg/resultshandling/reporter"
	"github.com/armosec/opa-utils/reporthandling"
)

type ISubmitObjects interface {
	SetResourcesReport() (*reporthandling.PostureReport, error)
	ListAllResources() (map[string]workloadinterface.IMetadata, error)
}

type SubmitInterfaces struct {
	SubmitObjects ISubmitObjects
	Reporter      reporter.IReport
	ClusterConfig cautils.ITenantConfig
}
