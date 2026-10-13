package imagescan

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/stretchr/testify/require"
)

func regionRegistries() []struct{ host, region string } {
	return []struct{ host, region string }{
		{"123456789012.dkr.ecr.eu-west-1.amazonaws.com", "eu-west-1"},
		{"123456789012.dkr.ecr-fips.us-east-2.amazonaws.com", "us-east-2"},
		{"123456789012.dkr-ecr.ap-southeast-2.on.aws", "ap-southeast-2"},
		{"123456789012.dkr-ecr-fips.us-gov-west-1.on.aws", "us-gov-west-1"},
		{"123456789012.dkr.ecr.cn-north-1.amazonaws.com.cn", "cn-north-1"},
		{"123456789012.dkr-ecr.cn-north-1.on.amazonwebservices.com.cn", "cn-north-1"},
		{"123456789012.dkr-ecr.cn-northwest-1.on.amazonwebservices.com.cn", "cn-northwest-1"},
	}
}

type regionECRAPI struct {
	call func(context.Context, *ecr.DescribeImageScanFindingsInput, ecr.Options) (*ecr.DescribeImageScanFindingsOutput, error)
}

func (api regionECRAPI) DescribeImageScanFindings(ctx context.Context, input *ecr.DescribeImageScanFindingsInput, opts ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error) {
	options := ecr.Options{Region: "us-east-1"}
	for _, apply := range opts {
		apply(&options)
	}
	return api.call(ctx, input, options)
}

func TestECRRegion_LoginUsesEverySupportedRegistryFamily(t *testing.T) {
	for _, tc := range regionRegistries() {
		t.Run(tc.host, func(t *testing.T) {
			adaptor := NewAWSECRAdaptor()
			adaptor.configProvider = func(_ context.Context, opts ...func(*config.LoadOptions) error) (aws.Config, error) {
				options := config.LoadOptions{Region: "us-east-1"}
				for _, apply := range opts {
					require.NoError(t, apply(&options))
				}
				require.Equal(t, tc.region, options.Region, "registry region must override environment defaults")
				return aws.Config{Region: options.Region}, nil
			}
			adaptor.clientFactory = func(cfg aws.Config) ECRAPI {
				require.Equal(t, tc.region, cfg.Region)
				return &mockECRClient{}
			}
			require.NoError(t, adaptor.Login(context.Background(), tc.host, RegistryCredentials{}))
			require.NotNil(t, adaptor.client)
		})
	}
}

func TestECRRegion_BothScanMethodsUseImageRegion(t *testing.T) {
	for _, tc := range regionRegistries() {
		for _, digest := range []bool{false, true} {
			t.Run(tc.host+"/"+map[bool]string{false: "tag", true: "digest"}[digest], func(t *testing.T) {
				image := ContainerImageIdentifier{Registry: tc.host, Repository: "team/app", Tag: "release"}
				if digest {
					image.Hash = "sha256:content"
				}
				calls := 0
				adaptor := &AWSECRAdaptor{client: regionECRAPI{call: func(_ context.Context, input *ecr.DescribeImageScanFindingsInput, opts ecr.Options) (*ecr.DescribeImageScanFindingsOutput, error) {
					calls++
					require.Equal(t, tc.region, opts.Region)
					require.Equal(t, "123456789012", aws.ToString(input.RegistryId))
					require.Equal(t, image.Repository, aws.ToString(input.RepositoryName))
					if digest {
						require.Equal(t, image.Hash, aws.ToString(input.ImageId.ImageDigest))
						require.Nil(t, input.ImageId.ImageTag)
					} else {
						require.Equal(t, image.Tag, aws.ToString(input.ImageId.ImageTag))
					}
					return &ecr.DescribeImageScanFindingsOutput{
						ImageScanStatus: &types.ImageScanStatus{Status: types.ScanStatusComplete},
						ImageScanFindings: &types.ImageScanFindings{Findings: []types.ImageScanFinding{
							{Name: aws.String("CVE-region"), Severity: types.FindingSeverityHigh},
						}},
					}, nil
				}}}
				statuses, err := adaptor.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{image})
				require.NoError(t, err)
				require.Len(t, statuses, 1)
				require.True(t, statuses[0].IsScanAvailable)
				reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
				require.NoError(t, err)
				require.Len(t, reports, 1)
				require.Equal(t, image, reports[0].ImageID)
				require.Len(t, reports[0].Vulnerabilities, 1)
				require.Equal(t, "CVE-region", reports[0].Vulnerabilities[0].ID)
				require.Equal(t, 2, calls)
			})
		}
	}
}

func TestECRRegion_MixedBatchKeepsPaginationInEachRegion(t *testing.T) {
	images := []ContainerImageIdentifier{
		{Registry: "123456789012.dkr.ecr.eu-west-1.amazonaws.com", Repository: "app", Tag: "release"},
		{Registry: "210987654321.dkr-ecr.ap-southeast-2.on.aws", Repository: "app", Tag: "release"},
	}
	regions := []string{"eu-west-1", "ap-southeast-2"}
	var calls []string
	adaptor := &AWSECRAdaptor{client: regionECRAPI{call: func(_ context.Context, input *ecr.DescribeImageScanFindingsInput, opts ecr.Options) (*ecr.DescribeImageScanFindingsOutput, error) {
		calls = append(calls, opts.Region)
		if aws.ToString(input.RegistryId) == "123456789012" {
			require.Equal(t, regions[0], opts.Region)
		} else {
			require.Equal(t, regions[1], opts.Region)
		}
		output := &ecr.DescribeImageScanFindingsOutput{
			ImageScanFindings: &types.ImageScanFindings{Findings: []types.ImageScanFinding{{Name: aws.String(opts.Region)}}},
		}
		if input.NextToken == nil {
			output.NextToken = aws.String("page2")
		} else {
			require.Equal(t, "page2", aws.ToString(input.NextToken))
		}
		return output, nil
	}}}
	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), images)
	require.NoError(t, err)
	require.Len(t, reports, 2)
	for i, report := range reports {
		require.Equal(t, images[i], report.ImageID)
		require.Len(t, report.Vulnerabilities, 2)
		for _, finding := range report.Vulnerabilities {
			require.Equal(t, regions[i], finding.ID)
		}
	}
	require.Equal(t, []string{regions[0], regions[0], regions[1], regions[1]}, calls)
}

func TestECRRegion_PartialErrorsDoNotChangeLaterImageRegion(t *testing.T) {
	images := []ContainerImageIdentifier{
		{Registry: "123456789012.dkr-ecr.eu-west-1.on.aws", Repository: "app", Tag: "release"},
		{Registry: "123456789012.dkr-ecr.ap-south-1.on.aws", Repository: "app", Tag: "release"},
	}
	fetchErr := errors.New("second page failed")
	adaptor := &AWSECRAdaptor{client: regionECRAPI{call: func(_ context.Context, input *ecr.DescribeImageScanFindingsInput, opts ecr.Options) (*ecr.DescribeImageScanFindingsOutput, error) {
		if opts.Region == "eu-west-1" && input.NextToken != nil {
			return nil, fetchErr
		}
		out := &ecr.DescribeImageScanFindingsOutput{
			ImageScanFindings: &types.ImageScanFindings{Findings: []types.ImageScanFinding{{Name: aws.String(opts.Region)}}},
		}
		if opts.Region == "eu-west-1" {
			out.NextToken = aws.String("page2")
		}
		return out, nil
	}}}
	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), images)
	require.ErrorIs(t, err, fetchErr)
	require.Len(t, reports, 2)
	require.Equal(t, "eu-west-1", reports[0].Vulnerabilities[0].ID)
	require.Equal(t, "ap-south-1", reports[1].Vulnerabilities[0].ID)
}

func TestECRRegion_InvalidRegistryDoesNotLoadConfig(t *testing.T) {
	for _, host := range []string{"", "public.ecr.aws", "12345.dkr.ecr.us-east-1.amazonaws.com", "123456789012.dkr-ecr.eu-west-1.evil.example"} {
		t.Run(host, func(t *testing.T) {
			adaptor := NewAWSECRAdaptor()
			adaptor.configProvider = func(context.Context, ...func(*config.LoadOptions) error) (aws.Config, error) {
				t.Fatal("invalid registry must be rejected before loading credentials")
				return aws.Config{}, nil
			}
			require.Error(t, adaptor.Login(context.Background(), host, RegistryCredentials{}))
			require.Nil(t, adaptor.client)
		})
	}
}

type regionHTTPClient struct {
	mu    sync.Mutex
	hosts []string
}

func (client *regionHTTPClient) Do(req *http.Request) (*http.Response, error) {
	client.mu.Lock()
	client.hosts = append(client.hosts, req.URL.Host)
	client.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/x-amz-json-1.1"}},
		Body:       io.NopCloser(strings.NewReader(`{"imageScanStatus":{"status":"COMPLETE"},"imageScanFindings":{"findings":[{"name":"CVE-sdk","severity":"HIGH"}]}}`)),
	}, nil
}

func TestECRRegion_RealSDKUsesImageEndpointWithoutMutatingClient(t *testing.T) {
	transport := &regionHTTPClient{}
	client := ecr.NewFromConfig(aws.Config{
		Region:      "us-east-1",
		Credentials: aws.AnonymousCredentials{},
		HTTPClient:  transport,
	})
	adaptor := &AWSECRAdaptor{client: client}
	images := []ContainerImageIdentifier{
		{Registry: "123456789012.dkr-ecr.eu-west-1.on.aws", Repository: "app", Tag: "v1"},
		{Registry: "123456789012.dkr.ecr.ap-south-1.amazonaws.com", Repository: "app", Tag: "v1"},
		{Registry: "123456789012.dkr-ecr.cn-north-1.on.amazonwebservices.com.cn", Repository: "app", Tag: "v1"},
	}
	statuses, err := adaptor.GetImagesScanStatus(context.Background(), images)
	require.NoError(t, err)
	require.Len(t, statuses, 3)
	for _, status := range statuses {
		require.True(t, status.IsScanAvailable)
	}
	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), images)
	require.NoError(t, err)
	require.Len(t, reports, 3)
	for _, report := range reports {
		require.Len(t, report.Vulnerabilities, 1)
	}
	want := []string{"api.ecr.eu-west-1.amazonaws.com", "api.ecr.ap-south-1.amazonaws.com", "api.ecr.cn-north-1.amazonaws.com.cn"}
	require.Equal(t, append(append([]string{}, want...), want...), transport.hosts)
	require.Equal(t, "us-east-1", client.Options().Region)
}

func TestECRRegion_ConfigFailureDoesNotConstructClient(t *testing.T) {
	sentinel := errors.New("credentials unavailable")
	adaptor := NewAWSECRAdaptor()
	adaptor.configProvider = func(_ context.Context, opts ...func(*config.LoadOptions) error) (aws.Config, error) {
		options := config.LoadOptions{}
		for _, apply := range opts {
			require.NoError(t, apply(&options))
		}
		require.Equal(t, "eu-west-1", options.Region)
		return aws.Config{}, sentinel
	}
	adaptor.clientFactory = func(aws.Config) ECRAPI {
		t.Fatal("failed configuration must not construct a client")
		return nil
	}
	err := adaptor.Login(context.Background(), "123456789012.dkr-ecr.eu-west-1.on.aws", RegistryCredentials{})
	require.ErrorIs(t, err, sentinel)
	require.Nil(t, adaptor.client)
}

func TestECRRegion_InvalidImagesNeverReachTheSDK(t *testing.T) {
	adaptor := &AWSECRAdaptor{client: regionECRAPI{call: func(context.Context, *ecr.DescribeImageScanFindingsInput, ecr.Options) (*ecr.DescribeImageScanFindingsOutput, error) {
		t.Fatal("an invalid registry cannot be used to construct region options")
		return nil, nil
	}}}
	for _, host := range []string{"", "public.ecr.aws", "123456789012.dkr-ecr..on.aws", "123456789012.ecr.eu-west-1.amazonaws.com"} {
		t.Run(host, func(t *testing.T) {
			image := ContainerImageIdentifier{Registry: host, Repository: "app", Tag: "v1"}
			statuses, err := adaptor.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{image})
			require.Error(t, err)
			require.Len(t, statuses, 1)
			require.False(t, statuses[0].IsScanAvailable)
			reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
			require.Error(t, err)
			require.Len(t, reports, 1)
			require.Empty(t, reports[0].Vulnerabilities)
		})
	}
}

func TestECRRegion_EmptyImageReferenceStillSkipsRequests(t *testing.T) {
	adaptor := &AWSECRAdaptor{client: regionECRAPI{call: func(context.Context, *ecr.DescribeImageScanFindingsInput, ecr.Options) (*ecr.DescribeImageScanFindingsOutput, error) {
		t.Fatal("an image without a tag or digest must be skipped")
		return nil, nil
	}}}
	image := ContainerImageIdentifier{Repository: "app"}
	statuses, err := adaptor.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{image})
	require.NoError(t, err)
	require.Len(t, statuses, 1)
	require.False(t, statuses[0].IsScanAvailable)
	reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
	require.NoError(t, err)
	require.Len(t, reports, 1)
	require.Empty(t, reports[0].Vulnerabilities)
}

func TestECRRegion_ConcurrentRealSDKRequestsDoNotCrossRegions(t *testing.T) {
	transport := &regionHTTPClient{}
	client := ecr.NewFromConfig(aws.Config{
		Region:      "us-east-1",
		Credentials: aws.AnonymousCredentials{},
		HTTPClient:  transport,
	})
	adaptor := &AWSECRAdaptor{client: client}
	var workers sync.WaitGroup
	for _, tc := range regionRegistries() {
		workers.Add(1)
		go func() {
			defer workers.Done()
			image := ContainerImageIdentifier{Registry: tc.host, Repository: "app", Tag: "v1"}
			statuses, err := adaptor.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{image})
			if err != nil {
				t.Errorf("%s: status: %v", tc.host, err)
				return
			}
			if len(statuses) != 1 || !statuses[0].IsScanAvailable {
				t.Errorf("%s: expected available scan", tc.host)
			}
			reports, err := adaptor.GetImagesVulnerabilities(context.Background(), []ContainerImageIdentifier{image})
			if err != nil {
				t.Errorf("%s: findings: %v", tc.host, err)
				return
			}
			if len(reports) != 1 || len(reports[0].Vulnerabilities) != 1 {
				t.Errorf("%s: missing findings", tc.host)
			}
		}()
	}
	workers.Wait()
	counts := make(map[string]int)
	for _, host := range transport.hosts {
		counts[host]++
	}
	want := make(map[string]int)
	for _, tc := range regionRegistries() {
		suffix := ".amazonaws.com"
		if strings.HasPrefix(tc.region, "cn-") {
			suffix += ".cn"
		}
		want["api.ecr."+tc.region+suffix] += 2
	}
	require.Equal(t, want, counts, "each image must use its own regional API endpoint")
	require.Equal(t, "us-east-1", client.Options().Region)
}

func TestECRRegion_ExplicitCredentialsRemainUnsupported(t *testing.T) {
	for _, credentials := range []RegistryCredentials{
		{Username: "fixture", Password: "password"},
		{Token: "fixture-token"},
	} {
		adaptor := NewAWSECRAdaptor()
		adaptor.configProvider = func(context.Context, ...func(*config.LoadOptions) error) (aws.Config, error) {
			t.Fatal("explicit credentials must not enter the default credential chain")
			return aws.Config{}, nil
		}
		require.ErrorContains(t, adaptor.Login(context.Background(), regionRegistries()[0].host, credentials), "unsupported")
	}
}

func TestECRRegion_ReLoginUsesNewRegistryRegion(t *testing.T) {
	adaptor := NewAWSECRAdaptor()
	var regions []string
	adaptor.configProvider = func(_ context.Context, opts ...func(*config.LoadOptions) error) (aws.Config, error) {
		var options config.LoadOptions
		for _, apply := range opts {
			require.NoError(t, apply(&options))
		}
		regions = append(regions, options.Region)
		return aws.Config{Region: options.Region}, nil
	}
	adaptor.clientFactory = func(cfg aws.Config) ECRAPI {
		return regionECRAPI{call: func(_ context.Context, _ *ecr.DescribeImageScanFindingsInput, options ecr.Options) (*ecr.DescribeImageScanFindingsOutput, error) {
			require.Equal(t, cfg.Region, options.Region)
			return &ecr.DescribeImageScanFindingsOutput{ImageScanStatus: &types.ImageScanStatus{Status: types.ScanStatusComplete}}, nil
		}}
	}
	for _, tc := range regionRegistries()[:3] {
		require.NoError(t, adaptor.Login(context.Background(), tc.host, RegistryCredentials{}))
		statuses, err := adaptor.GetImagesScanStatus(context.Background(), []ContainerImageIdentifier{{Registry: tc.host, Repository: "app", Tag: "latest"}})
		require.NoError(t, err)
		require.True(t, statuses[0].IsScanAvailable)
	}
	require.Equal(t, []string{"eu-west-1", "us-east-2", "ap-southeast-2"}, regions)
}
