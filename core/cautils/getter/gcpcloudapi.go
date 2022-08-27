package getter

import (
	"context"

	containeranalysis "cloud.google.com/go/containeranalysis/apiv1"
	grafeaspb "google.golang.org/genproto/googleapis/grafeas/v1"
)

type GCPCloudAPI struct {
	credentialsPath string
	context         context.Context
	client          *containeranalysis.Client
	projectID       string
	occs            []*grafeaspb.Occurrence
	credentials     bool
	loggedIn        bool
}

var globalGCPCloudAPIConnector *GCPCloudAPI

func GetGlobalGCPCloudAPIConnector() *GCPCloudAPI {

	globalGCPCloudAPIConnector = &GCPCloudAPI{
		context: context.Background(),
		credentials: false,
		loggedIn: false,
	}
	return globalGCPCloudAPIConnector
}

func (api *GCPCloudAPI) SetClient(client *containeranalysis.Client) {
    api.client = client
}

func (api *GCPCloudAPI) GetcrediantialsPath() string          { return api.credentialsPath }
func (api *GCPCloudAPI) Getclient() *containeranalysis.Client { return api.client }
func (api *GCPCloudAPI) GetloggedIn() bool                    { return api.loggedIn }
func (api *GCPCloudAPI) GetProjectID() string                 { return api.projectID }
func (api *GCPCloudAPI) GetCredentials() bool                 { return api.credentials }
func (api *GCPCloudAPI) GetContext() context.Context { return api.context}
 