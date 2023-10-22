package cliinterfaces

import (
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling/reporter"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

type ISubmitObjects interface {
	SetResourcesReport() (*reporthandlingv2.PostureReport, error)
	ListAllResources() (map[string]workloadinterface.IMetadata, error)
}

type SubmitInterfaces struct {
	SubmitObjects ISubmitObjects
	Reporter      reporter.IReport
	ClusterConfig cautils.ITenantConfig
}
