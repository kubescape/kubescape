package getter

import (
	"context"

	containeranalysis "cloud.google.com/go/containeranalysis/apiv1"
)

type GCPCloudAPI struct {
	credentialsPath string
	context         context.Context
	client          *containeranalysis.Client
	projectID       string
	credentials     bool
	loggedIn        bool
}

var globalGCPCloudAPIConnector *GCPCloudAPI

func GetGlobalGCPCloudAPIConnector() *GCPCloudAPI {

	globalGCPCloudAPIConnector = &GCPCloudAPI{
		context:     context.Background(),
		credentials: false,
		loggedIn:    false,
	}
	return globalGCPCloudAPIConnector
}

func (api *GCPCloudAPI) SetClient(client *containeranalysis.Client) {
	api.client = client
}

func (api *GCPCloudAPI) GetCrediantialsPath() string          { return api.credentialsPath }
func (api *GCPCloudAPI) GetClient() *containeranalysis.Client { return api.client }
func (api *GCPCloudAPI) GetLoggedIn() bool                    { return api.loggedIn }
func (api *GCPCloudAPI) GetProjectID() string                 { return api.projectID }
func (api *GCPCloudAPI) GetCredentials() bool                 { return api.credentials }
func (api *GCPCloudAPI) GetContext() context.Context          { return api.context }
