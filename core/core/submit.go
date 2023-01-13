package core

import (
	"context"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/cautils/getter"
	"github.com/kubescape/kubescape/v2/core/meta/cliinterfaces"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
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
	submitInterfaces.Reporter.DisplayReportURL()

	return nil
}

func (ks *Kubescape) SubmitExceptions(ctx context.Context, credentials *cautils.Credentials, excPath string) error {
	logger.L().Info("submitting exceptions", helpers.String("path", excPath))

	// load cached config
	tenantConfig := getTenantConfig(credentials, "", "", getKubernetesApi())
	if err := tenantConfig.SetTenant(); err != nil {
		logger.L().Ctx(ctx).Error("failed setting account ID", helpers.Error(err))
	}

	// load exceptions from file
	loader := getter.NewLoadPolicy([]string{excPath})
	exceptions, err := loader.GetExceptions("")
	if err != nil {
		return err
	}

	// login kubescape SaaS
	ksCloudAPI := getter.GetKSCloudAPIConnector()
	if err := ksCloudAPI.Login(); err != nil {
		return err
	}

	if err := ksCloudAPI.PostExceptions(exceptions); err != nil {
		return err
	}
	logger.L().Success("Exceptions submitted successfully")

	return nil
}
