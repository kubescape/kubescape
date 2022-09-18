package core

import (
	"fmt"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v2/core/cautils/getter"
	v1 "github.com/kubescape/kubescape/v2/core/meta/datastructures/v1"
)

func (ks *Kubescape) DeleteExceptions(delExceptions *v1.DeleteExceptions) error {

	// load cached config
	getTenantConfig(&delExceptions.Credentials, "", "", getKubernetesApi())

	// login kubescape SaaS
	ksCloudAPI := getter.GetKSCloudAPIConnector()
	if err := ksCloudAPI.Login(); err != nil {
		return err
	}

	for i := range delExceptions.Exceptions {
		exceptionName := delExceptions.Exceptions[i]
		if exceptionName == "" {
			continue
		}
		logger.L().Info("Deleting exception", helpers.String("name", exceptionName))
		if err := ksCloudAPI.DeleteException(exceptionName); err != nil {
			return fmt.Errorf("failed to delete exception '%s', reason: %s", exceptionName, err.Error())
		}
		logger.L().Success("Exception deleted successfully")
	}

	return nil
}
