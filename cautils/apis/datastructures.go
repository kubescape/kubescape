package apis

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/docker/docker/api/types"
)

// WebsocketScanCommand trigger scan thru the websocket
type WebsocketScanCommand struct {
	// CustomerGUID string `json:"customerGUID"`
	ImageTag      string `json:"imageTag"`
	Wlid          string `json:"wlid"`
	IsScanned     bool   `json:"isScanned"`
	ContainerName string `json:"containerName"`
	JobID         string `json:"jobID,omitempty"`
	LastAction    int    `json:"actionIDN"`
	// ImageHash     string `json:"imageHash"`
	Credentials *types.AuthConfig `json:"credentials,omitempty"`
}

//taken from BE
// ElasticRespTotal holds the total struct in Elastic array response
type ElasticRespTotal struct {
	Value    int    `json:"value"`
	Relation string `json:"relation"`
}

// V2ListResponse holds the response of some list request with some metadata
type V2ListResponse struct {
	Total    ElasticRespTotal `json:"total"`
	Response interface{}      `json:"response"`
	// Cursor for quick access to the next page. Not supported yet
	Cursor string `json:"cursor"`
}

// Oauth2Customer returns inside the "ca_groups" field in claims section of
// Oauth2 verification process
type Oauth2Customer struct {
	CustomerName string `json:"customerName"`
	CustomerGUID string `json:"customerGUID"`
}

type LoginObject struct {
	Authorization string `json:"authorization"`
	GUID          string
	Cookies       []*http.Cookie
	Expires       string
}

type SafeMode struct {
	Reporter        string `json:"reporter"`                // "Agent"
	Action          string `json:"action,omitempty"`        // "action"
	Wlid            string `json:"wlid"`                    // CAA_WLID
	PodName         string `json:"podName"`                 // CAA_POD_NAME
	InstanceID      string `json:"instanceID"`              // CAA_POD_NAME
	ContainerName   string `json:"containerName,omitempty"` // CAA_CONTAINER_NAME
	ProcessName     string `json:"processName,omitempty"`
	ProcessID       int    `json:"processID,omitempty"`
	ProcessCMD      string `json:"processCMD,omitempty"`
	ComponentGUID   string `json:"componentGUID,omitempty"` // CAA_GUID
	StatusCode      int    `json:"statusCode"`              // 0/1/2
	ProcessExitCode int    `json:"processExitCode"`         // 0 +
	Timestamp       int64  `json:"timestamp"`
	Message         string `json:"message,omitempty"` // any string
	JobID           string `json:"jobID,omitempty"`   // any string
	Compatible      *bool  `json:"compatible,omitempty"`
}

func (safeMode *SafeMode) Json() string {
	b, err := json.Marshal(*safeMode)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s", b)
}
