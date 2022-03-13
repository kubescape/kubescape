package core

import (
	"fmt"

	"github.com/armosec/kubescape/core/cautils/getter"
	"github.com/armosec/kubescape/core/cautils/logger"
	"github.com/armosec/kubescape/core/cautils/logger/helpers"
	v1 "github.com/armosec/kubescape/core/meta/datastructures/v1"
)

func (ks *Kubescape) DeleteExceptions(delExceptions *v1.DeleteExceptions) error {

	// load cached config
	getTenantConfig(delExceptions.Account, "", getKubernetesApi())

	// login kubescape SaaS
	armoAPI := getter.GetArmoAPIConnector()
	if err := armoAPI.Login(); err != nil {
		return err
	}

	for i := range delExceptions.Exceptions {
		exceptionName := delExceptions.Exceptions[i]
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
