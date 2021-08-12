package probes

import (
	"fmt"
	"net/http"
)

// server initialization
const (
	ReadinessPath = "readiness"
	ReadinessPort = "8000"
)

// InitReadinessV1 initialize readiness handler
func InitReadinessV1(isReadinessReady *bool) {
	http.HandleFunc(fmt.Sprintf("/v1/%s", ReadinessPath), func(w http.ResponseWriter, _ *http.Request) {
		if *isReadinessReady {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	},
	)
	http.ListenAndServe(":8000", nil)
}
