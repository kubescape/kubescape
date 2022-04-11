package listener

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/armosec/kubescape/v2/core/cautils/logger"
	"github.com/armosec/kubescape/v2/core/cautils/logger/helpers"
)

// RecoverFunc recover function for http requests
func RecoverFunc(w http.ResponseWriter) {
	if err := recover(); err != nil {
		logger.L().Error("", helpers.Error(fmt.Errorf("%v", err)))
		w.WriteHeader(http.StatusInternalServerError)
		bErr, _ := json.Marshal(err)
		w.Write(bErr)
	}
}
