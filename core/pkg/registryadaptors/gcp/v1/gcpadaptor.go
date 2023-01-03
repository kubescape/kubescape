package v1

import (
	"fmt"

	containeranalysis "cloud.google.com/go/containeranalysis/apiv1"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v2/core/cautils/getter"
	"github.com/kubescape/kubescape/v2/core/pkg/registryadaptors/registryvulnerabilities"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	grafeaspb "google.golang.org/genproto/googleapis/grafeas/v1"
)

func NewGCPAdaptor(GCPCloudAPI *getter.GCPCloudAPI) *GCPAdaptor {
	return &GCPAdaptor{
		GCPCloudAPI: GCPCloudAPI,
	}
}

func (GCPAdaptor *GCPAdaptor) Login() error {
	client, err := containeranalysis.NewClient(GCPAdaptor.GCPCloudAPI.GetContext(), option.WithCredentialsFile(GCPAdaptor.GCPCloudAPI.GetCredentialsPath()))
	if err != nil {
		return err
	}
	GCPAdaptor.GCPCloudAPI.SetClient(client)
	return nil
}

func (GCPAdaptor *GCPAdaptor) GetImagesVulnerabilities(imageIDs []registryvulnerabilities.ContainerImageIdentifier) ([]registryvulnerabilities.ContainerImageVulnerabilityReport, error) {
	resultList := make([]registryvulnerabilities.ContainerImageVulnerabilityReport, 0)
	for _, toPin := range imageIDs {
		imageID := toPin
		result, err := GCPAdaptor.GetImageVulnerability(&imageID)
		if err != nil {
			logger.L().Debug("failed to get image vulnerabilities", helpers.String("image", imageID.Tag), helpers.Error(err))
			continue
		}

		resultList = append(resultList, *result)
	}

	return resultList, nil
}

func (GCPAdaptor *GCPAdaptor) GetImageVulnerability(imageID *registryvulnerabilities.ContainerImageIdentifier) (*registryvulnerabilities.ContainerImageVulnerabilityReport, error) {

	resourceUrl := fmt.Sprintf("https://%s", imageID.Tag)

	req := &grafeaspb.ListOccurrencesRequest{
		Parent: fmt.Sprintf("projects/%s", GCPAdaptor.GCPCloudAPI.GetProjectID()),
		Filter: fmt.Sprintf(`resourceUrl=%q`, resourceUrl),
	}

	it := GCPAdaptor.GCPCloudAPI.GetClient().GetGrafeasClient().ListOccurrences(GCPAdaptor.GCPCloudAPI.GetContext(), req)
	occs := []*grafeaspb.Occurrence{}
	var count int
	for {
		occ, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		occs = append(occs, occ)
		count++
	}
	vulnerabilities := responseObjectToVulnerabilities(occs, count)

	resultImageVulnerabilityReport := registryvulnerabilities.ContainerImageVulnerabilityReport{
		ImageID:         *imageID,
		Vulnerabilities: vulnerabilities,
	}
	return &resultImageVulnerabilityReport, nil
}

func (GCPAdaptor *GCPAdaptor) DescribeAdaptor() string {
	return "GCP image vulnerabilities scanner, docs: https://cloud.google.com/container-analysis/docs/container-analysis"
}

func (GCPAdaptor *GCPAdaptor) GetImagesInformation(imageIDs []registryvulnerabilities.ContainerImageIdentifier) ([]registryvulnerabilities.ContainerImageInformation, error) {
	// TODO
	return []registryvulnerabilities.ContainerImageInformation{}, nil
}

func (GCPAdaptor *GCPAdaptor) GetImagesScanStatus(imageIDs []registryvulnerabilities.ContainerImageIdentifier) ([]registryvulnerabilities.ContainerImageScanStatus, error) {
	// TODO
	return []registryvulnerabilities.ContainerImageScanStatus{}, nil
}
