package core

import (
	"context"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/meta/cliinterfaces"

	logger "github.com/kubescape/go-logger"
)

func (ks *Kubescape) Submit(ctx context.Context, submitInterfaces cliinterfaces.SubmitInterfaces) error {

	// list resources
	report, err := submitInterfaces.SubmitObjects.SetResourcesReport()
	if err != nil {
		return err
	}
	allresources, err := submitInterfaces.SubmitObjects.ListAllResources()
	if err != nil {
		return err
	}
	// report
	o := &cautils.OPASessionObj{
		Report:       report,
		AllResources: allresources,
		Metadata:     &report.Metadata,
	}
	if err := submitInterfaces.Reporter.Submit(ctx, o); err != nil {
		return err
	}
	logger.L().Success("Data has been submitted successfully")
	submitInterfaces.Reporter.DisplayMessage()

	return nil
}
