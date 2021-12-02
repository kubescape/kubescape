package cliinterfaces

import (
	"github.com/armosec/kubescape/cautils"
	"github.com/armosec/kubescape/resultshandling/reporter"
	"github.com/armosec/opa-utils/reporthandling"
)

type ISubmitObjects interface {
	SetResourcesReport() (*reporthandling.PostureReport, error)
}

type SubmitInterfaces struct {
	SubmitObjects ISubmitObjects
	Reporter      reporter.IReport
	ClusterConfig cautils.ITenantConfig
}
