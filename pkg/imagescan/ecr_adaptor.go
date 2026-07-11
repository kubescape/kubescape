package imagescan

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

// ECRAPI defines the interface for the ECR functions we use, enabling mocking in tests.
type ECRAPI interface {
	DescribeImageScanFindings(ctx context.Context, params *ecr.DescribeImageScanFindingsInput, optFns ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error)
	BatchGetImage(ctx context.Context, params *ecr.BatchGetImageInput, optFns ...func(*ecr.Options)) (*ecr.BatchGetImageOutput, error)
}

// AWSECRAdaptor implements IContainerImageVulnerabilityAdaptor for AWS ECR.
type AWSECRAdaptor struct {
	client ECRAPI
}

// NewAWSECRAdaptor creates a new ECR adaptor instance.
func NewAWSECRAdaptor() *AWSECRAdaptor {
	return &AWSECRAdaptor{}
}

// Login authenticates with AWS. It prioritizes the default credential chain.
func (a *AWSECRAdaptor) Login(ctx context.Context, registry string, credentials RegistryCredentials) error {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("unable to load AWS SDK config: %w", err)
	}

	a.client = ecr.NewFromConfig(cfg)
	return nil
}

// DescribeAdaptor provides a string description of the adaptor for help purposes.
func (a *AWSECRAdaptor) DescribeAdaptor() string {
	return "AWS Elastic Container Registry (ECR) Vulnerability Adaptor"
}

// GetImagesScanStatus retrieves the scan status for a list of image identifiers.
func (a *AWSECRAdaptor) GetImagesScanStatus(ctx context.Context, imageIDs []ContainerImageIdentifier) ([]ContainerImageScanStatus, error) {
	if a.client == nil {
		return nil, fmt.Errorf("ECR client not initialized, call Login first")
	}

	var statuses []ContainerImageScanStatus

	for _, imageID := range imageIDs {
		input := &ecr.DescribeImageScanFindingsInput{
			RepositoryName: aws.String(imageID.Repository),
			ImageId: &types.ImageIdentifier{
				ImageDigest: aws.String(imageID.Hash),
				ImageTag:    aws.String(imageID.Tag),
			},
			MaxResults: aws.Int32(1),
		}

		if imageID.Tag == "" {
			input.ImageId.ImageTag = nil
		}
		if imageID.Hash == "" {
			input.ImageId.ImageDigest = nil
		}

		status := ContainerImageScanStatus{
			ImageID:         imageID,
			IsScanAvailable: false,
			IsBomAvailable:  false,
		}

		out, err := a.client.DescribeImageScanFindings(ctx, input)
		if err != nil {
			statuses = append(statuses, status)
			continue
		}

		if out.ImageScanStatus != nil && out.ImageScanStatus.Status == types.ScanStatusComplete {
			status.IsScanAvailable = true
			if out.ImageScanFindings != nil && out.ImageScanFindings.ImageScanCompletedAt != nil {
				status.LastScanDate = *out.ImageScanFindings.ImageScanCompletedAt
			}
		}
		statuses = append(statuses, status)
	}

	return statuses, nil
}

// GetImagesVulnerabilities retrieves the vulnerability reports for a list of image identifiers.
func (a *AWSECRAdaptor) GetImagesVulnerabilities(ctx context.Context, imageIDs []ContainerImageIdentifier) ([]ContainerImageVulnerabilityReport, error) {
	if a.client == nil {
		return nil, fmt.Errorf("ECR client not initialized, call Login first")
	}

	var reports []ContainerImageVulnerabilityReport

	for _, imageID := range imageIDs {
		report := ContainerImageVulnerabilityReport{
			ImageID:         imageID,
			Vulnerabilities: []Vulnerability{},
		}

		input := &ecr.DescribeImageScanFindingsInput{
			RepositoryName: aws.String(imageID.Repository),
			ImageId: &types.ImageIdentifier{
				ImageDigest: aws.String(imageID.Hash),
				ImageTag:    aws.String(imageID.Tag),
			},
		}

		for {
			out, err := a.client.DescribeImageScanFindings(ctx, input)
			if err != nil {
				break
			}
			if out.ImageScanFindings != nil {
				for _, finding := range out.ImageScanFindings.Findings {
					report.Vulnerabilities = append(report.Vulnerabilities, Vulnerability{
						ID:          aws.ToString(finding.Name),
						Severity:    string(finding.Severity),
						Description: aws.ToString(finding.Description),
						Links:       []string{aws.ToString(finding.Uri)},
					})
				}
			}

			if out.NextToken == nil {
				break
			}
			input.NextToken = out.NextToken
		}

		reports = append(reports, report)
	}

	return reports, nil
}

// GetImagesInformation retrieves the BOM and manifest information for a list of image identifiers.
func (a *AWSECRAdaptor) GetImagesInformation(ctx context.Context, imageIDs []ContainerImageIdentifier) ([]ContainerImageInformation, error) {
	if a.client == nil {
		return nil, fmt.Errorf("ECR client not initialized, call Login first")
	}

	var infos []ContainerImageInformation

	for _, imageID := range imageIDs {
		info := ContainerImageInformation{
			ImageID: imageID,
			Bom:     []string{},
		}

		input := &ecr.BatchGetImageInput{
			RepositoryName: aws.String(imageID.Repository),
			ImageIds: []types.ImageIdentifier{
				{
					ImageDigest: aws.String(imageID.Hash),
					ImageTag:    aws.String(imageID.Tag),
				},
			},
		}

		if imageID.Tag == "" {
			input.ImageIds[0].ImageTag = nil
		}
		if imageID.Hash == "" {
			input.ImageIds[0].ImageDigest = nil
		}

		out, err := a.client.BatchGetImage(ctx, input)
		if err != nil || len(out.Images) == 0 {
			infos = append(infos, info)
			continue
		}

		infos = append(infos, info)
	}

	return infos, nil
}
