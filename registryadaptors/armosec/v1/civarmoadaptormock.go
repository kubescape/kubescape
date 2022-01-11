package v1

import (
	"fmt"

	"github.com/armosec/kubescape/registryadaptors/registryvulnerabilities"
)

type ArmoCivAdaptorMock struct {
	registry   string
	accountId  string
	clientId   string
	accessKey  string
	feToken    FeLoginResponse
	armoUrls   ArmoBeConfiguration
	authCookie string
}

func NewArmoAdaptorMock(registry string, credentials map[string]string) (*ArmoCivAdaptorMock, error) {
	var accountId string
	var accessKey string
	var clientId string
	var ok bool
	if accountId, ok = credentials["accountId"]; !ok {
		return nil, fmt.Errorf("define accountId in credentials")
	}
	if clientId, ok = credentials["clientId"]; !ok {
		return nil, fmt.Errorf("define clientId in credentials")
	}
	if accessKey, ok = credentials["accessKey"]; !ok {
		return nil, fmt.Errorf("define accessKey in credentials")
	}
	armoCivAdaptor := ArmoCivAdaptorMock{
		registry:  registry,
		accountId: accountId,
		clientId:  clientId,
		accessKey: accessKey,
	}
	// err := armoCivAdaptorMock.initializeUrls()
	// if err != nil {
	// 	return nil, err
	// }
	return &armoCivAdaptor, nil
}

func (armoCivAdaptorMock *ArmoCivAdaptorMock) Login() error {

	return nil
}
func (armoCivAdaptorMock *ArmoCivAdaptorMock) GetImagesVulnerabilities(imageIDs []registryvulnerabilities.ContainerImageIdentifier) ([]registryvulnerabilities.ContainerImageVulnerabilityReport, error) {
	resultList := make([]registryvulnerabilities.ContainerImageVulnerabilityReport, 0)
	for _, imageID := range imageIDs {
		result, err := armoCivAdaptorMock.GetImageVulnerability(&imageID)
		if err == nil {
			resultList = append(resultList, *result)
		}
	}
	return resultList, nil
}

func (armoCivAdaptorMock *ArmoCivAdaptorMock) GetImageVulnerability(imageID *registryvulnerabilities.ContainerImageIdentifier) (*registryvulnerabilities.ContainerImageVulnerabilityReport, error) {
	return &registryvulnerabilities.ContainerImageVulnerabilityReport{}, nil
}

func (armoCivAdaptorMock *ArmoCivAdaptorMock) DescribeAdaptor() string {
	// TODO
	return ""
}

func (armoCivAdaptorMock *ArmoCivAdaptorMock) GetImagesInformation(imageIDs []registryvulnerabilities.ContainerImageIdentifier) ([]registryvulnerabilities.ContainerImageInformation, error) {
	// TODO
	return []registryvulnerabilities.ContainerImageInformation{}, nil
}

func (armoCivAdaptorMock *ArmoCivAdaptorMock) GetImagesScanStatus(imageIDs []registryvulnerabilities.ContainerImageIdentifier) ([]registryvulnerabilities.ContainerImageScanStatus, error) {
	// TODO
	return []registryvulnerabilities.ContainerImageScanStatus{}, nil
}
