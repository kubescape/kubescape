package k8sinterface

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/docker/docker/api/types"
)

// For GCR there are some permissions one need to assign in order to allow ARMO to pull images:
// https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity
// gcloud iam service-accounts create armo-controller-sa
// gcloud projects add-iam-policy-binding <PROJECT_NAME> --role roles/storage.objectViewer --member "serviceAccount:armo-controller-sa@<PROJECT_NAME>.iam.gserviceaccount.com"
// gcloud iam service-accounts add-iam-policy-binding   --role roles/iam.workloadIdentityUser   --member "serviceAccount:<PROJECT_NAME>.svc.id.goog[cyberarmor-system/ca-controller-service-account]"   armo-controller-sa@<PROJECT_NAME>.iam.gserviceaccount.com
// kubectl annotate serviceaccount --overwrite   --namespace cyberarmor-system   ca-controller-service-account iam.gke.io/gcp-service-account=armo-controller-sa@<PROJECT_NAME>.iam.gserviceaccount.com

const (
	gcrDefaultServiceAccountName = "default"
	// armoServiceAccountName = "ca-controller-service-account"
)

var (
	httpClient = http.Client{Timeout: 5 * time.Second}
)

// CheckIsECRImage check if this image is suspected as ECR hosted image
func CheckIsECRImage(imageTag string) bool {
	return strings.Contains(imageTag, "dkr.ecr")
}

// GetLoginDetailsForECR return user name + password using the default iam-role OR ~/.aws/config of the machine
func GetLoginDetailsForECR(imageTag string) (string, string, error) {
	// imageTag := "015253967648.dkr.ecr.eu-central-1.amazonaws.com/armo:1"
	imageTagSlices := strings.Split(imageTag, ".")
	repo := imageTagSlices[0]
	region := imageTagSlices[3]
	mySession := session.Must(session.NewSession())
	ecrClient := ecr.New(mySession, aws.NewConfig().WithRegion(region))
	input := &ecr.GetAuthorizationTokenInput{
		RegistryIds: []*string{&repo},
	}
	res, err := ecrClient.GetAuthorizationToken(input)
	if err != nil {
		return "", "", fmt.Errorf("in PullFromECR, failed to GetAuthorizationToken: %v", err)
	}
	res64 := (*res.AuthorizationData[0].AuthorizationToken)
	resB, err := base64.StdEncoding.DecodeString(res64)
	if err != nil {
		return "", "", fmt.Errorf("in PullFromECR, failed to DecodeString: %v", err)
	}
	delimiterIdx := bytes.IndexByte(resB, ':')
	// userName := resB[:delimiterIdx]
	// resB = resB[delimiterIdx+1:]
	// resB, err = base64.StdEncoding.DecodeString(string(resB))
	// if err != nil {
	// 	t.Errorf("failed to DecodeString #2: %v\n\n", err)
	// }
	return string(resB[:delimiterIdx]), string(resB[delimiterIdx+1:]), nil
}

func CheckIsACRImage(imageTag string) bool {
	// atest1.azurecr.io/go-inf:1
	return strings.Contains(imageTag, ".azurecr.io/")
}

type azureADDResponseJson struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    string `json:"expires_in"`
	ExpiresOn    string `json:"expires_on"`
	NotBefore    string `json:"not_before"`
	Resource     string `json:"resource"`
	TokenType    string `json:"token_type"`
}

func getAzureAADAccessToken() (string, error) {
	msi_endpoint, err := url.Parse("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01")
	if err != nil {
		return "", fmt.Errorf("creating URL : %v", err)
	}
	msi_parameters := url.Values{}
	msi_parameters.Add("resource", "https://management.azure.com/")
	msi_parameters.Add("api-version", "2018-02-01")
	msi_endpoint.RawQuery = msi_parameters.Encode()
	req, err := http.NewRequest("GET", msi_endpoint.String(), nil)
	if err != nil {
		return "", fmt.Errorf("creating HTTP request : %v", err)
	}
	req.Header.Add("Metadata", "true")

	// Call managed services for Azure resources token endpoint
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("calling token endpoint : %v", err)
	}

	// Pull out response body
	responseBytes, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return "", fmt.Errorf("reading response body : %v", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("azure ActiveDirectory AT resp: %v, %v", resp.Status, string(responseBytes))
	}

	// Unmarshall response body into struct
	var r azureADDResponseJson
	err = json.Unmarshal(responseBytes, &r)
	if err != nil {
		return "", fmt.Errorf("unmarshalling the response: %v", err)
	}
	return r.AccessToken, nil
}

// GetLoginDetailsForAzurCR return user name + password to use
func GetLoginDetailsForAzurCR(imageTag string) (string, string, error) {
	// imageTag := "atest1.azurecr.io/go-inf:1"
	imageTagSlices := strings.Split(imageTag, "/")
	azureIdensAT, err := getAzureAADAccessToken()
	if err != nil {
		return "", "", err
	}
	atMap := make(map[string]interface{})
	azureIdensATSlices := strings.Split(azureIdensAT, ".")
	if len(azureIdensATSlices) < 2 {
		return "", "", fmt.Errorf("len(azureIdensATSlices) < 2")
	}
	resB, err := base64.RawStdEncoding.DecodeString(azureIdensATSlices[1])
	if err != nil {
		return "", "", fmt.Errorf("in GetLoginDetailsForAzurCR, failed to DecodeString: %v, %s", err, azureIdensATSlices[1])
	}
	if err := json.Unmarshal(resB, &atMap); err != nil {
		return "", "", fmt.Errorf("failed to unmarshal azureIdensAT: %v, %s", err, string(resB))
	}
	// excahnging AAD for ACR refresh token
	refreshToken, err := excahngeAzureAADAccessTokenForACRRefreshToken(imageTagSlices[0], fmt.Sprintf("%v", atMap["tid"]), azureIdensAT)
	if err != nil {
		return "", "", fmt.Errorf("failed to excahngeAzureAADAccessTokenForACRRefreshToken: %v, registry: %s, tenantID: %s, azureAADAT: %s", err, imageTagSlices[0], fmt.Sprintf("%v", atMap["tid"]), azureIdensAT)
	}

	return "00000000-0000-0000-0000-000000000000", refreshToken, nil
}

func excahngeAzureAADAccessTokenForACRRefreshToken(registry, tenantID, azureAADAT string) (string, error) {
	msi_parameters := url.Values{}
	msi_parameters.Add("service", registry)
	msi_parameters.Add("grant_type", "access_token")
	msi_parameters.Add("tenant", tenantID)
	msi_parameters.Add("access_token", azureAADAT)
	postBodyStr := msi_parameters.Encode()
	req, err := http.NewRequest("POST", fmt.Sprintf("https://%v/oauth2/exchange", registry), strings.NewReader(postBodyStr))
	if err != nil {
		return "", fmt.Errorf("creating HTTP request : %v", err)
	}
	req.Header.Add("Metadata", "true")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Call managed services for Azure resources token endpoint
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("calling token endpoint : %v", err)
	}

	// Pull out response body
	responseBytes, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return "", fmt.Errorf("reading response body : %v", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("azure exchange AT resp: %v, %v", resp.Status, string(responseBytes))
	}
	resultMap := make(map[string]string)
	err = json.Unmarshal(responseBytes, &resultMap)
	if err != nil {
		return "", fmt.Errorf("unmarshalling the response: %v", err)
	}
	return resultMap["refresh_token"], nil
}

func CheckIsGCRImage(imageTag string) bool {
	// gcr.io/elated-pottery-310110/golang-inf:2
	return strings.Contains(imageTag, "gcr.io/")
}

// GetLoginDetailsForGCR return user name + password to use
func GetLoginDetailsForGCR(imageTag string) (string, string, error) {
	msi_endpoint, err := url.Parse(fmt.Sprintf("http://169.254.169.254/computeMetadata/v1/instance/service-accounts/%s/token", gcrDefaultServiceAccountName))
	if err != nil {
		return "", "", fmt.Errorf("creating URL : %v", err)
	}
	req, err := http.NewRequest("GET", msi_endpoint.String(), nil)
	if err != nil {
		return "", "", fmt.Errorf("creating HTTP request : %v", err)
	}
	req.Header.Add("Metadata-Flavor", "Google")

	// Call managed services for Azure resources token endpoint
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("calling token endpoint : %v", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("HTTP Status : %v, make sure the '%s' service account is configured for ARMO pod", resp.Status, gcrDefaultServiceAccountName)
	}
	defer resp.Body.Close()
	respMap := make(map[string]interface{})
	if err := json.NewDecoder(resp.Body).Decode(&respMap); err != nil {
		return "", "", fmt.Errorf("json Decode : %v", err)
	}
	return "oauth2accesstoken", fmt.Sprintf("%v", respMap["access_token"]), nil
}

func GetCloudVendorRegistryCredentials(imageTag string) (map[string]types.AuthConfig, error) {
	secrets := map[string]types.AuthConfig{}
	var errRes error
	if CheckIsACRImage(imageTag) {
		userName, password, err := GetLoginDetailsForAzurCR(imageTag)
		if err != nil {
			errRes = fmt.Errorf("failed to GetLoginDetailsForACR(%s): %v", imageTag, err)
		} else {
			secrets[imageTag] = types.AuthConfig{
				Username: userName,
				Password: password,
			}
		}
	}

	if CheckIsECRImage(imageTag) {
		userName, password, err := GetLoginDetailsForECR(imageTag)
		if err != nil {
			errRes = fmt.Errorf("failed to GetLoginDetailsForECR(%s): %v", imageTag, err)
		} else {
			secrets[imageTag] = types.AuthConfig{
				Username: userName,
				Password: password,
			}
		}
	}

	if CheckIsGCRImage(imageTag) {
		userName, password, err := GetLoginDetailsForGCR(imageTag)
		if err != nil {
			errRes = fmt.Errorf("failed to GetLoginDetailsForGCR(%s): %v", imageTag, err)
		} else {
			secrets[imageTag] = types.AuthConfig{
				Username: userName,
				Password: password,
			}
		}
	}

	return secrets, errRes
}
