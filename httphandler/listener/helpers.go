package listener

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

// RecoverFunc recover function for http requests
func RecoverFunc(w http.ResponseWriter) {
	if err := recover(); err != nil {
		errMsg := fmt.Sprintf("%v", err)
		logger.L().Error("", helpers.Error(fmt.Errorf("%s", errMsg)))
		w.WriteHeader(http.StatusInternalServerError)
		bErr, _ := json.Marshal(errMsg)
		w.Write(bErr)
	}
}
