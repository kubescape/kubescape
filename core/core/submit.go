package core

import (
	"github.com/armosec/kubescape/v2/core/cautils"
	"github.com/armosec/kubescape/v2/core/cautils/getter"
	"github.com/armosec/kubescape/v2/core/meta/cliinterfaces"

	logger "github.com/dwertent/go-logger"
	"github.com/dwertent/go-logger/helpers"
)

func (ks *Kubescape) Submit(submitInterfaces cliinterfaces.SubmitInterfaces) error {

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
	if err := submitInterfaces.Reporter.Submit(o); err != nil {
		return err
	}
	logger.L().Success("Data has been submitted successfully")
	submitInterfaces.Reporter.DisplayReportURL()

	return nil
}

func (ks *Kubescape) SubmitExceptions(credentials *cautils.Credentials, excPath string) error {
	logger.L().Info("submitting exceptions", helpers.String("path", excPath))

	// load cached config
	tenantConfig := getTenantConfig(credentials, "", getKubernetesApi())
	if err := tenantConfig.SetTenant(); err != nil {
		logger.L().Error("failed setting account ID", helpers.Error(err))
	}

	// load exceptions from file
	loader := getter.NewLoadPolicy([]string{excPath})
	exceptions, err := loader.GetExceptions("")
	if err != nil {
		return err
	}

	// login kubescape SaaS
	armoAPI := getter.GetKSCloudAPIConnector()
	if err := armoAPI.Login(); err != nil {
		return err
	}

	if err := armoAPI.PostExceptions(exceptions); err != nil {
		return err
	}
	logger.L().Success("Exceptions submitted successfully")

	return nil
}
