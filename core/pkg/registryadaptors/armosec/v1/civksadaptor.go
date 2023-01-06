package v1

import (
	"encoding/json"
	"fmt"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v2/core/cautils/getter"
	"github.com/kubescape/kubescape/v2/core/pkg/containerscan"
	"github.com/kubescape/kubescape/v2/core/pkg/registryadaptors/registryvulnerabilities"
)

func NewKSAdaptor(api *getter.KSCloudAPI) *KSCivAdaptor {
	return &KSCivAdaptor{
		ksCloudAPI: api,
	}
}

func (ksCivAdaptor *KSCivAdaptor) Login() error {
	if ksCivAdaptor.ksCloudAPI.IsLoggedIn() {
		return nil
	}
	return ksCivAdaptor.ksCloudAPI.Login()
}
func (ksCivAdaptor *KSCivAdaptor) GetImagesVulnerabilities(imageIDs []registryvulnerabilities.ContainerImageIdentifier) ([]registryvulnerabilities.ContainerImageVulnerabilityReport, error) {
	resultList := make([]registryvulnerabilities.ContainerImageVulnerabilityReport, 0)
	for _, toPin := range imageIDs {
		imageID := toPin
		result, err := ksCivAdaptor.GetImageVulnerability(&imageID)
		if err != nil {
			logger.L().Debug("failed to get image vulnerabilities", helpers.String("image", imageID.Tag), helpers.Error(err))
			continue
		}

		resultList = append(resultList, *result)
	}

	return resultList, nil
}

func (ksCivAdaptor *KSCivAdaptor) GetImageVulnerability(imageID *registryvulnerabilities.ContainerImageIdentifier) (*registryvulnerabilities.ContainerImageVulnerabilityReport, error) {
	// First
	containerScanId, err := ksCivAdaptor.getImageLastScanId(imageID)
	if err != nil {
		return nil, err
	}
	if containerScanId == "" {
		return nil, fmt.Errorf("last scan ID is empty")
	}

	filter := []map[string]string{{"containersScanID": containerScanId}}
	pageSize := 300
	pageNumber := 1
	request := V2ListRequest{PageSize: &pageSize, PageNum: &pageNumber, InnerFilters: filter, OrderBy: "timestamp:desc"}
	requestBody, _ := json.Marshal(request)
	requestUrl := fmt.Sprintf("https://%s/api/v1/vulnerability/scanResultsDetails?customerGUID=%s", ksCivAdaptor.ksCloudAPI.GetCloudAPIURL(), ksCivAdaptor.ksCloudAPI.GetAccountID())

	resp, err := ksCivAdaptor.ksCloudAPI.Post(requestUrl, map[string]string{"Content-Type": "application/json"}, requestBody)
	if err != nil {
		return nil, err
	}

	scanDetailsResult := struct {
		Total struct {
			Value    int    `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		Response containerscan.VulnerabilitiesList `json:"response"`
		Cursor   string                            `json:"cursor"`
	}{}

	err = json.Unmarshal([]byte(resp), &scanDetailsResult)
	if err != nil {
		return nil, err
	}

	vulnerabilities := responseObjectToVulnerabilities(scanDetailsResult.Response)

	resultImageVulnerabilityReport := registryvulnerabilities.ContainerImageVulnerabilityReport{
		ImageID:         *imageID,
		Vulnerabilities: vulnerabilities,
	}

	return &resultImageVulnerabilityReport, nil
}

func (ksCivAdaptor *KSCivAdaptor) DescribeAdaptor() string {
	return "armo image vulnerabilities scanner, docs: https://hub.armosec.io/docs/configuration-of-image-vulnerabilities"
}

func (ksCivAdaptor *KSCivAdaptor) GetImagesInformation(imageIDs []registryvulnerabilities.ContainerImageIdentifier) ([]registryvulnerabilities.ContainerImageInformation, error) {
	// TODO
	return []registryvulnerabilities.ContainerImageInformation{}, nil
}

func (ksCivAdaptor *KSCivAdaptor) GetImagesScanStatus(imageIDs []registryvulnerabilities.ContainerImageIdentifier) ([]registryvulnerabilities.ContainerImageScanStatus, error) {
	// TODO
	return []registryvulnerabilities.ContainerImageScanStatus{}, nil
}
