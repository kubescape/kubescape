package v1

import (
	"github.com/kubescape/kubescape/v2/core/pkg/registryadaptors/registryvulnerabilities"
	grafeaspb "google.golang.org/genproto/googleapis/grafeas/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type GCPAdaptorMock struct {
	resultList []registryvulnerabilities.ContainerImageVulnerabilityReport
}

func NewGCPAdaptorMock() (*GCPAdaptorMock, error) {
	return &GCPAdaptorMock{}, nil
}

func (GCPAdaptorMock *GCPAdaptorMock) Login() error {
	return nil
}

func (GCPAdaptorMock *GCPAdaptorMock) GetImagesVulnerabilities(imageIDs []registryvulnerabilities.ContainerImageIdentifier) ([]registryvulnerabilities.ContainerImageVulnerabilityReport, error) {
	resultList := make([]registryvulnerabilities.ContainerImageVulnerabilityReport, 0)
	for _, toPin := range imageIDs {
		imageID := toPin
		result, err := GCPAdaptorMock.GetImageVulnerability(&imageID)
		if err != nil {
			return nil, err
		}

		resultList = append(resultList, *result)

		return resultList, nil //nolint:staticcheck // we return at once and shorten the mocked result
	}

	GCPAdaptorMock.resultList = resultList
	return GCPAdaptorMock.resultList, nil
}

func (GCPAdaptorMock *GCPAdaptorMock) GetImageVulnerability(imageID *registryvulnerabilities.ContainerImageIdentifier) (*registryvulnerabilities.ContainerImageVulnerabilityReport, error) {
	vulnerability := []*grafeaspb.Occurrence_Vulnerability{}
	occurrence := []*grafeaspb.Occurrence{}
	arr := GetMockData()

	for i := range arr {
		if imageID.Tag == "gcr.io/myproject/nginx@sha256:2XXXXX" && i == 4 {
			break
		}
		vulnerability = append(vulnerability, &grafeaspb.Occurrence_Vulnerability{
			Vulnerability: &grafeaspb.VulnerabilityOccurrence{
				Type:             arr[i].Type,
				CvssScore:        arr[i].CvssScore,
				ShortDescription: arr[i].ShortDescription,
				PackageIssue: []*grafeaspb.VulnerabilityOccurrence_PackageIssue{
					{
						FixedVersion: &grafeaspb.Version{
							FullName: arr[i].FixedVersion,
						},
						AffectedVersion: &grafeaspb.Version{
							FullName: arr[i].AffectedVersion,
						},
						AffectedCpeUri:  arr[i].AffectedCPEURI,
						AffectedPackage: arr[i].AffectedPackage,
					},
				},
				FixAvailable: arr[i].FixAvailable,
			},
		})

		occurrence = append(occurrence, &grafeaspb.Occurrence{
			Name:     arr[i].Name,
			Kind:     grafeaspb.NoteKind_ATTESTATION,
			NoteName: arr[i].Notename,
			CreateTime: &timestamppb.Timestamp{
				Seconds: arr[i].CreatedTime,
			},
			UpdateTime: &timestamppb.Timestamp{
				Seconds: arr[i].UpdatedTime,
			},
			Details: vulnerability[i],
		})
	}

	vulnerabilities := responseObjectToVulnerabilities(occurrence, 5)

	resultImageVulnerabilityReport := registryvulnerabilities.ContainerImageVulnerabilityReport{
		ImageID:         *imageID,
		Vulnerabilities: vulnerabilities,
	}
	return &resultImageVulnerabilityReport, nil
}

func (GCPAdaptorMock *GCPAdaptorMock) DescribeAdaptor() string {
	// TODO
	return ""
}

func (GCPAdaptorMock *GCPAdaptorMock) GetImagesInformation(imageIDs []registryvulnerabilities.ContainerImageIdentifier) ([]registryvulnerabilities.ContainerImageInformation, error) {
	// TODO
	return []registryvulnerabilities.ContainerImageInformation{}, nil
}

func (GCPAdaptorMock *GCPAdaptorMock) GetImagesScanStatus(imageIDs []registryvulnerabilities.ContainerImageIdentifier) ([]registryvulnerabilities.ContainerImageScanStatus, error) {
	// TODO
	return []registryvulnerabilities.ContainerImageScanStatus{}, nil
}

//==============================================================================================================================
//==============================================================================================================================
//==============================================================================================================================

func GetMockData() []Mock {
	arr := []Mock{
		{
			Name:             "projects/stable-furnace-356005/occurrences/41fd9fec-6fab-4531-a4ee-e7b97d518554",
			Notename:         "projects/goog-vulnz/notes/CVE-2009-4487",
			CvssScore:        6.8,
			CreatedTime:      1661061853,
			UpdatedTime:      1661061853,
			Type:             "OS",
			ShortDescription: "CVE-2009-4487",
			AffectedCPEURI:   "cpe:/o:debian:debian_linux:11",
			AffectedPackage:  "nginx",
			FixAvailable:     true,
			AffectedVersion:  "1.23.1-1~bullseye",
			FixedVersion:     "",
		},
		{
			Name:             "projects/stable-furnace-356005/occurrences/b28fa29f-5c2b-45c7-9727-2f1f02ed1957",
			Notename:         "projects/goog-vulnz/notes/CVE-2017-17740",
			CvssScore:        2.3,
			CreatedTime:      3237628,
			UpdatedTime:      5989893,
			Type:             "OS",
			ShortDescription: "CVE-2017-17740",
			AffectedCPEURI:   "cpe:/o:debian:debian_linux:11",
			AffectedPackage:  "openldap",
			FixAvailable:     false,
			AffectedVersion:  "1.3.5",
			FixedVersion:     "1.3.5",
		},
		{
			Name:             "projects/stable-furnace-356005/occurrences/b28fa29f-5c2b-45c7-9727-2f1f02ed1957",
			Notename:         "projects/goog-vulnz/notes/CVE-2017-17740",
			CvssScore:        2.3,
			CreatedTime:      3237628,
			UpdatedTime:      5989893,
			Type:             "OS",
			ShortDescription: "CVE-2017-17740",
			AffectedCPEURI:   "cpe:/o:debian:debian_linux:11",
			AffectedPackage:  "openldap",
			FixAvailable:     false,
			AffectedVersion:  "1.3.5",
			FixedVersion:     "1.3.5",
		},
		{
			Name:             "projects/stable-furnace-356005/occurrences/b28fa29f-5c2b-45c7-9727-2f1f02ed1957",
			Notename:         "projects/goog-vulnz/notes/CVE-2017-17740",
			CvssScore:        2.3,
			CreatedTime:      3237628,
			UpdatedTime:      5989893,
			Type:             "OS",
			ShortDescription: "CVE-2017-17740",
			AffectedCPEURI:   "cpe:/o:debian:debian_linux:11",
			AffectedPackage:  "openldap",
			FixAvailable:     false,
			AffectedVersion:  "1.3.5",
			FixedVersion:     "1.3.5",
		},
		{
			Name:             "projects/stable-furnace-356005/occurrences/b28fa29f-5c2b-45c7-9727-2f1f02ed1957",
			Notename:         "projects/goog-vulnz/notes/CVE-2017-17740",
			CvssScore:        2.3,
			CreatedTime:      3237628,
			UpdatedTime:      5989893,
			Type:             "OS",
			ShortDescription: "CVE-2017-17740",
			AffectedCPEURI:   "cpe:/o:debian:debian_linux:11",
			AffectedPackage:  "openldap",
			FixAvailable:     false,
			AffectedVersion:  "1.3.5",
			FixedVersion:     "1.3.5",
		},
	}

	return arr
}
