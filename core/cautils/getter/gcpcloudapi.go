package getter

import (
	"context"

	containeranalysis "cloud.google.com/go/containeranalysis/apiv1"
)

type GCPCloudAPI struct {
	credentialsPath  string
	context          context.Context
	client           *containeranalysis.Client
	projectID        string
	credentialsCheck bool
}

var globalGCPCloudAPIConnector *GCPCloudAPI

func GetGlobalGCPCloudAPIConnector() *GCPCloudAPI {
	// need to move this to function where creds will be added 
	globalGCPCloudAPIConnector = &GCPCloudAPI{
		context:          context.Background(),
	}
	return globalGCPCloudAPIConnector
}

func (api *GCPCloudAPI) SetClient(client *containeranalysis.Client) {
	api.client = client
}

func (api *GCPCloudAPI) GetCrediantialsPath() string          { return api.credentialsPath }
func (api *GCPCloudAPI) GetClient() *containeranalysis.Client { return api.client }
func (api *GCPCloudAPI) GetProjectID() string                 { return api.projectID }
func (api *GCPCloudAPI) GetCredentialsCheck() bool            { return api.credentialsCheck }
func (api *GCPCloudAPI) GetContext() context.Context          { return api.context }
