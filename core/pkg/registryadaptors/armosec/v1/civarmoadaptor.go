package v1

import (
	"encoding/json"
	"fmt"

	"github.com/armosec/kubescape/v2/core/cautils/getter"
	"github.com/armosec/kubescape/v2/core/pkg/containerscan"
	"github.com/armosec/kubescape/v2/core/pkg/registryadaptors/registryvulnerabilities"
	logger "github.com/dwertent/go-logger"
	"github.com/dwertent/go-logger/helpers"
)

func NewArmoAdaptor(armoAPI *getter.KSCloudAPI) *ArmoCivAdaptor {
	return &ArmoCivAdaptor{
		armoAPI: armoAPI,
	}
}

func (armoCivAdaptor *ArmoCivAdaptor) Login() error {
	if armoCivAdaptor.armoAPI.IsLoggedIn() {
		return nil
	}
	return armoCivAdaptor.armoAPI.Login()
}
func (armoCivAdaptor *ArmoCivAdaptor) GetImagesVulnerabilities(imageIDs []registryvulnerabilities.ContainerImageIdentifier) ([]registryvulnerabilities.ContainerImageVulnerabilityReport, error) {
	resultList := make([]registryvulnerabilities.ContainerImageVulnerabilityReport, 0)
	for _, imageID := range imageIDs {
		result, err := armoCivAdaptor.GetImageVulnerability(&imageID)
		if err == nil {
			resultList = append(resultList, *result)
		} else {
			logger.L().Debug("failed to get image vulnerabilities", helpers.String("image", imageID.Tag), helpers.Error(err))
		}
	}
	return resultList, nil
}

func (armoCivAdaptor *ArmoCivAdaptor) GetImageVulnerability(imageID *registryvulnerabilities.ContainerImageIdentifier) (*registryvulnerabilities.ContainerImageVulnerabilityReport, error) {
	// First
	containerScanId, err := armoCivAdaptor.getImageLastScanId(imageID)
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
	requestUrl := fmt.Sprintf("https://%s/api/v1/vulnerability/scanResultsDetails?customerGUID=%s", armoCivAdaptor.armoAPI.GetApiURL(), armoCivAdaptor.armoAPI.GetAccountID())

	resp, err := armoCivAdaptor.armoAPI.Post(requestUrl, map[string]string{"Content-Type": "application/json"}, requestBody)
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

func (armoCivAdaptor *ArmoCivAdaptor) DescribeAdaptor() string {
	return "armo image vulnerabilities scanner, docs: https://hub.armosec.io/docs/configuration-of-image-vulnerabilities"
}

func (armoCivAdaptor *ArmoCivAdaptor) GetImagesInformation(imageIDs []registryvulnerabilities.ContainerImageIdentifier) ([]registryvulnerabilities.ContainerImageInformation, error) {
	// TODO
	return []registryvulnerabilities.ContainerImageInformation{}, nil
}

func (armoCivAdaptor *ArmoCivAdaptor) GetImagesScanStatus(imageIDs []registryvulnerabilities.ContainerImageIdentifier) ([]registryvulnerabilities.ContainerImageScanStatus, error) {
	// TODO
	return []registryvulnerabilities.ContainerImageScanStatus{}, nil
}
