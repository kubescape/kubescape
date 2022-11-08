package getter

import (
	"context"
	"os"

	containeranalysis "cloud.google.com/go/containeranalysis/apiv1"
)

type GCPCloudAPI struct {
	credentialsPath  string
	context          context.Context
	client           *containeranalysis.Client
	projectID        string
	credentialsCheck bool
}

func GetGlobalGCPCloudAPIConnector() *GCPCloudAPI {

	if os.Getenv("KS_GCP_CREDENTIALS_PATH") == "" || os.Getenv("KS_GCP_PROJECT_ID") == "" {
		return &GCPCloudAPI{
			credentialsCheck: false,
		}
	} else {
		return &GCPCloudAPI{
			context:          context.Background(),
			credentialsPath:  os.Getenv("KS_GCP_CREDENTIALS_PATH"),
			projectID:        os.Getenv("KS_GCP_PROJECT_ID"),
			credentialsCheck: true,
		}
	}
}

func (api *GCPCloudAPI) SetClient(client *containeranalysis.Client) {
	api.client = client
}

func (api *GCPCloudAPI) GetCredentialsPath() string           { return api.credentialsPath }
func (api *GCPCloudAPI) GetClient() *containeranalysis.Client { return api.client }
func (api *GCPCloudAPI) GetProjectID() string                 { return api.projectID }
func (api *GCPCloudAPI) GetCredentialsCheck() bool            { return api.credentialsCheck }
func (api *GCPCloudAPI) GetContext() context.Context          { return api.context }
