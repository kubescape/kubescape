package imagescan

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

// ECRAPI defines the interface for the ECR functions we use, enabling mocking in tests.
type ECRAPI interface {
	DescribeImageScanFindings(ctx context.Context, params *ecr.DescribeImageScanFindingsInput, optFns ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error)
}

type awsConfigProvider func(ctx context.Context, optFns ...func(*config.LoadOptions) error) (aws.Config, error)
type ecrClientFactory func(cfg aws.Config) ECRAPI

const maxECRVulnerabilityPages = 1000

// ecrRegistryAccount identifies the registry owning an image. Omitting
// RegistryId makes ECR query the credentials' account instead, which is not
// necessarily the image's account when cross-account access is configured.
func ecrRegistryAccount(registry string) (string, error) {
	parts := strings.Split(registry, ".")
	validSuffix := len(parts) == 6 || (len(parts) == 7 && parts[6] == "cn")
	if !validSuffix || parts[1] != "dkr" || (parts[2] != "ecr" && parts[2] != "ecr-fips") ||
		parts[3] == "" || parts[4] != "amazonaws" || parts[5] != "com" {
		return "", fmt.Errorf("invalid private ECR registry %q", registry)
	}
	account := parts[0]
	if len(account) != 12 {
		return "", fmt.Errorf("ECR registry %q must contain a 12-digit account ID", registry)
	}
	for _, digit := range account {
		if digit < '0' || digit > '9' {
			return "", fmt.Errorf("ECR registry %q must contain a 12-digit account ID", registry)
		}
	}
	return account, nil
}

// AWSECRAdaptor implements IContainerImageVulnerabilityAdaptor for AWS ECR.
type AWSECRAdaptor struct {
	client         ECRAPI
	configProvider awsConfigProvider
	clientFactory  ecrClientFactory
}

// NewAWSECRAdaptor creates a new ECR adaptor instance.
func NewAWSECRAdaptor() *AWSECRAdaptor {
	return &AWSECRAdaptor{
		configProvider: config.LoadDefaultConfig,
		clientFactory: func(cfg aws.Config) ECRAPI {
			return ecr.NewFromConfig(cfg)
		},
	}
}

// Login authenticates with AWS. It prioritizes the default credential chain.
// Explicit credentials passed via RegistryCredentials are intentionally unsupported
// as AWS SDK v2 relies heavily on IAM Roles for Service Accounts (IRSA) and default configuration.
func (a *AWSECRAdaptor) Login(ctx context.Context, registry string, credentials RegistryCredentials) error {
	if credentials.Username != "" || credentials.Password != "" || credentials.Token != "" {
		return fmt.Errorf("explicit credentials are intentionally unsupported for AWS ECR; use AWS IRSA or default credential chain")
	}

	var opts []func(*config.LoadOptions) error

	// Extract region from registry URL (e.g., <account>.dkr.ecr.<region>.amazonaws.com)
	parts := strings.Split(registry, ".")
	if len(parts) >= 6 && parts[1] == "dkr" && parts[2] == "ecr" && parts[4] == "amazonaws" && parts[5] == "com" {
		opts = append(opts, config.WithRegion(parts[3]))
	}

	cfg, err := a.configProvider(ctx, opts...)
	if err != nil {
		return fmt.Errorf("unable to load AWS SDK config: %w", err)
	}

	a.client = a.clientFactory(cfg)
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

	return ProcessImages(imageIDs,
		func(imageID ContainerImageIdentifier) (ContainerImageScanStatus, error) {
			status := ContainerImageScanStatus{
				ImageID:         imageID,
				IsScanAvailable: false,
				IsBomAvailable:  false,
			}

			if imageID.Hash == "" && imageID.Tag == "" {
				return status, nil
			}
			account, err := ecrRegistryAccount(imageID.Registry)
			if err != nil {
				return status, err
			}

			var ecrImageID types.ImageIdentifier
			if imageID.Hash != "" {
				ecrImageID.ImageDigest = aws.String(imageID.Hash)
			} else if imageID.Tag != "" {
				ecrImageID.ImageTag = aws.String(imageID.Tag)
			}

			input := &ecr.DescribeImageScanFindingsInput{
				RegistryId:     aws.String(account),
				RepositoryName: aws.String(imageID.Repository),
				ImageId:        &ecrImageID,
				MaxResults:     aws.Int32(1),
			}

			out, err := a.client.DescribeImageScanFindings(ctx, input)
			if err != nil {
				return status, fmt.Errorf("failed to describe image scan findings for repository %s: %w", imageID.Repository, err)
			}

			if out.ImageScanStatus != nil {
				status.Status = mapECRScanStatus(out.ImageScanStatus)
				if status.Status == ScanStatusScanned {
					status.IsScanAvailable = true
					if out.ImageScanFindings != nil && out.ImageScanFindings.ImageScanCompletedAt != nil {
						status.LastScanDate = *out.ImageScanFindings.ImageScanCompletedAt
					}
				}
			}

			return status, nil
		},
	)
}

func mapECRScanStatus(scanStatus *types.ImageScanStatus) ScanStatus {
	if scanStatus == nil || scanStatus.Status == "" {
		return ""
	}
	switch scanStatus.Status {
	case types.ScanStatusComplete, types.ScanStatusActive:
		return ScanStatusScanned
	case types.ScanStatusInProgress, types.ScanStatusPending:
		return ScanStatusQueued
	case types.ScanStatusUnsupportedImage:
		return ScanStatusUnsupported
	case types.ScanStatusFailed:
		return ScanStatusFailed
	default:
		return ScanStatusUnknown
	}
}

// GetImagesVulnerabilities retrieves the vulnerability reports for a list of image identifiers.
func (a *AWSECRAdaptor) GetImagesVulnerabilities(ctx context.Context, imageIDs []ContainerImageIdentifier) ([]ContainerImageVulnerabilityReport, error) {
	if a.client == nil {
		return nil, fmt.Errorf("ECR client not initialized, call Login first")
	}

	return ProcessImages(imageIDs,
		func(imageID ContainerImageIdentifier) (ContainerImageVulnerabilityReport, error) {
			report := ContainerImageVulnerabilityReport{
				ImageID:         imageID,
				Vulnerabilities: []Vulnerability{},
			}

			if imageID.Hash == "" && imageID.Tag == "" {
				return report, nil
			}
			account, err := ecrRegistryAccount(imageID.Registry)
			if err != nil {
				return report, err
			}

			var ecrImageID types.ImageIdentifier
			if imageID.Hash != "" {
				ecrImageID.ImageDigest = aws.String(imageID.Hash)
			} else if imageID.Tag != "" {
				ecrImageID.ImageTag = aws.String(imageID.Tag)
			}

			input := &ecr.DescribeImageScanFindingsInput{
				RegistryId:     aws.String(account),
				RepositoryName: aws.String(imageID.Repository),
				ImageId:        &ecrImageID,
			}

			var fetchErr error
			var providerStatus ScanStatus
			seenTokens := make(map[string]struct{})

			for pagesFetched := 0; ; pagesFetched++ {
				out, err := a.client.DescribeImageScanFindings(ctx, input)
				if err != nil {
					fetchErr = err
					break
				}
				if providerStatus == "" && out.ImageScanStatus != nil {
					providerStatus = mapECRScanStatus(out.ImageScanStatus)
				}
				if out.ImageScanFindings != nil {
					for _, finding := range out.ImageScanFindings.Findings {
						report.Vulnerabilities = append(report.Vulnerabilities, Vulnerability{
							ID:          aws.ToString(finding.Name),
							Severity:    NormalizeSeverity(string(finding.Severity)),
							Description: aws.ToString(finding.Description),
							Links:       []string{aws.ToString(finding.Uri)},
						})
					}
					for _, finding := range out.ImageScanFindings.EnhancedFindings {
						vulnerability := Vulnerability{
							Severity:    NormalizeSeverity(aws.ToString(finding.Severity)),
							Description: aws.ToString(finding.Description),
						}

						if details := finding.PackageVulnerabilityDetails; details != nil {
							vulnerability.ID = aws.ToString(details.VulnerabilityId)
							vulnerability.Links = append(vulnerability.Links, details.ReferenceUrls...)

							if sourceURL := aws.ToString(details.SourceUrl); sourceURL != "" && !slices.Contains(vulnerability.Links, sourceURL) {
								vulnerability.Links = append(vulnerability.Links, sourceURL)
							}
						}
						if vulnerability.ID == "" {
							vulnerability.ID = aws.ToString(finding.Title)
						}

						report.Vulnerabilities = append(report.Vulnerabilities, vulnerability)
					}
				}

				nextToken, hasNextPage, cursorErr := nextECRVulnerabilityToken(
					out.NextToken,
					seenTokens,
					pagesFetched+1,
				)
				if cursorErr != nil {
					fetchErr = cursorErr
					break
				}
				if !hasNextPage {
					break
				}
				input.NextToken = aws.String(nextToken)
			}

			report.Status = providerStatus

			if fetchErr != nil {
				return report, fmt.Errorf("failed to fetch vulnerabilities for repository %s: %w", imageID.Repository, fetchErr)
			}

			return report, nil
		},
	)
}

// nextECRVulnerabilityToken validates the continuation token before another
// request is made. ECR normally returns nil on the final page. A non-nil empty
// token, a token already observed earlier in the chain, or a continuation
// after the page budget has been exhausted cannot make forward progress and
// must fail instead of repeatedly downloading and appending the same page.
func nextECRVulnerabilityToken(nextToken *string, seen map[string]struct{}, pagesFetched int) (string, bool, error) {
	if nextToken == nil {
		return "", false, nil
	}

	token := aws.ToString(nextToken)
	if strings.TrimSpace(token) == "" {
		return "", false, fmt.Errorf("ecr vulnerability pagination returned an empty continuation token")
	}
	if _, exists := seen[token]; exists {
		return "", false, fmt.Errorf("ecr vulnerability pagination repeated continuation token %q", token)
	}
	if pagesFetched >= maxECRVulnerabilityPages {
		return "", false, fmt.Errorf("exceeded max pages (%d) fetching ecr vulnerabilities", maxECRVulnerabilityPages)
	}

	seen[token] = struct{}{}
	return token, true, nil
}

// GetImagesInformation retrieves the BOM and manifest information for a list of image identifiers.
func (a *AWSECRAdaptor) GetImagesInformation(ctx context.Context, imageIDs []ContainerImageIdentifier) ([]ContainerImageInformation, error) {
	if a.client == nil {
		return nil, fmt.Errorf("ECR client not initialized, call Login first")
	}
	return FetchImagesInformation(imageIDs)
}

// Destroy cleans up any persistent resources used by the adaptor.
func (a *AWSECRAdaptor) Destroy() error {
	return nil
}
