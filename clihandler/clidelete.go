package clihandler

import (
	"fmt"

	"github.com/armosec/kubescape/cautils/getter"
	"github.com/armosec/kubescape/cautils/logger"
	"github.com/armosec/kubescape/cautils/logger/helpers"
)

func DeleteExceptions(accountID string, exceptions []string) error {

	// load cached config
	getTenantConfig(accountID, "", getKubernetesApi())

	// login kubescape SaaS
	armoAPI := getter.GetArmoAPIConnector()
	if err := armoAPI.Login(); err != nil {
		return err
	}

	for i := range exceptions {
		exceptionName := exceptions[i]
		if exceptionName == "" {
			continue
		}
		logger.L().Info("Deleting exception", helpers.String("name", exceptionName))
		if err := armoAPI.DeleteException(exceptionName); err != nil {
			return fmt.Errorf("failed to delete exception '%s', reason: %s", exceptionName, err.Error())
		}
		logger.L().Success("Exception deleted successfully")
	}

	return nil
}
