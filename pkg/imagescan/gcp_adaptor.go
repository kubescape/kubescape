package imagescan

import (
	"context"
	"errors"
	"fmt"
	"strings"

	containeranalysis "cloud.google.com/go/containeranalysis/apiv1"
	grafeas "cloud.google.com/go/grafeas/apiv1"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"google.golang.org/api/iterator"
	grafeaspb "google.golang.org/genproto/googleapis/grafeas/v1"
)

// GrafeasIterator defines an interface for iterating over occurrences
type GrafeasIterator interface {
	Next() (*grafeaspb.Occurrence, error)
}

// GrafeasIteratorWrapper wraps the actual *grafeas.OccurrenceIterator to implement GrafeasIterator
type GrafeasIteratorWrapper struct {
	it *grafeas.OccurrenceIterator
}

func (w *GrafeasIteratorWrapper) Next() (*grafeaspb.Occurrence, error) {
	return w.it.Next()
}

// GCPAPI defines the interface for the GCP Grafeas functions we use, enabling mocking in tests.
type GCPAPI interface {
	ListOccurrences(ctx context.Context, req *grafeaspb.ListOccurrencesRequest, opts ...interface{}) GrafeasIterator
}

// gcpAPIWrapper implements GCPAPI by wrapping the real grafeas.Client
type gcpAPIWrapper struct {
	client *grafeas.Client
}

func (g *gcpAPIWrapper) ListOccurrences(ctx context.Context, req *grafeaspb.ListOccurrencesRequest, opts ...interface{}) GrafeasIterator {
	it := g.client.ListOccurrences(ctx, req)
	return &GrafeasIteratorWrapper{it: it}
}

// GCPAdaptor implements IContainerImageVulnerabilityAdaptor for GCP Artifact Registry.
type GCPAdaptor struct {
	client       GCPAPI
	owningClient *containeranalysis.Client
	projectID    string
}

// NewGCPAdaptor creates a new GCP adaptor instance.
func NewGCPAdaptor() *GCPAdaptor {
	return &GCPAdaptor{}
}

// setOwningClient installs c as the adaptor's owning containeranalysis
// client, closing any previously held client first. Without this, repeated
// Login calls on the same adaptor instance would leak the previous client's
// underlying gRPC connection pool.
func (a *GCPAdaptor) setOwningClient(c *containeranalysis.Client) {
	if a.owningClient != nil {
		if closeErr := a.owningClient.Close(); closeErr != nil {
			logger.L().Warning("failed to close previous gcp container analysis client", helpers.Error(closeErr))
		}
	}

	a.owningClient = c
	a.client = &gcpAPIWrapper{client: c.GetGrafeasClient()}
}

// Login authenticates with GCP. It prioritizes the default application credentials.
// Explicit credentials passed via RegistryCredentials are intentionally unsupported
// as GCP SDK relies heavily on Workload Identity and Application Default Credentials.
func (a *GCPAdaptor) Login(ctx context.Context, registry string, credentials RegistryCredentials) error {
	if credentials.Username != "" || credentials.Password != "" || credentials.Token != "" {
		return fmt.Errorf("explicit credentials are intentionally unsupported for gcp; use Application Default Credentials or Workload Identity")
	}

	parts := strings.Split(registry, "/")
	var newProjectID string
	if len(parts) >= 2 {
		newProjectID = parts[1]
	} else {
		return fmt.Errorf("invalid gcp registry format: expected location-docker.pkg.dev/project/repository, got %s", registry)
	}

	if a.owningClient != nil {
		a.client = nil // Stage clearing of client
		if err := a.owningClient.Close(); err != nil {
			return fmt.Errorf("failed to close previous container analysis client: %w", err)
		}
		a.owningClient = nil
	} else {
		a.client = nil
	}

	c, err := containeranalysis.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("unable to load gcp container analysis client: %w", err)
	}

	a.projectID = newProjectID
	a.setOwningClient(c)

	// Fail-fast probe to ensure identity is valid
	req := &grafeaspb.ListOccurrencesRequest{
		Parent:   fmt.Sprintf("projects/%s", a.projectID),
		Filter:   "kind=\"DISCOVERY\"",
		PageSize: 1,
	}
	it := a.client.ListOccurrences(ctx, req)
	if _, err := it.Next(); err != nil && err != iterator.Done {
		a.owningClient.Close()
		a.owningClient = nil
		a.client = nil
		return fmt.Errorf("failed to authenticate or access gcp project %s: %w", a.projectID, err)
	}

	return nil
}

// DescribeAdaptor provides a string description of the adaptor for help purposes.
func (a *GCPAdaptor) DescribeAdaptor() string {
	return "GCP Artifact Registry (GAR) Vulnerability Adaptor"
}

// GetImagesScanStatus retrieves the scan status for a list of image identifiers.
func (a *GCPAdaptor) GetImagesScanStatus(ctx context.Context, imageIDs []ContainerImageIdentifier) ([]ContainerImageScanStatus, error) {
	if a.client == nil {
		return nil, fmt.Errorf("gcp client not initialized, call login first")
	}

	var statuses []ContainerImageScanStatus
	var aggErr error

	for _, imageID := range imageIDs {
		status := ContainerImageScanStatus{
			ImageID:         imageID,
			IsScanAvailable: false,
			IsBomAvailable:  false,
		}

		if imageID.Hash == "" {
			statuses = append(statuses, status)
			continue
		}

		req := &grafeaspb.ListOccurrencesRequest{
			Parent: fmt.Sprintf("projects/%s", a.projectID),
			Filter: buildGrafeasFilter("DISCOVERY", imageID),
		}

		it := a.client.ListOccurrences(ctx, req)
		for {
			occurrence, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				fetchErr := fmt.Errorf("failed to query scan status for repository %s: %w", imageID.Repository, err)
				logger.L().Warning("skipping image scan status due to api error", helpers.Error(fetchErr))
				aggErr = errors.Join(aggErr, fetchErr)
				break
			}

			if occurrence != nil && occurrence.GetDiscovery() != nil {
				discovery := occurrence.GetDiscovery()
				if discovery != nil && discovery.GetAnalysisStatus() == grafeaspb.DiscoveryOccurrence_FINISHED_SUCCESS {
					status.IsScanAvailable = true
					if occurrence.UpdateTime != nil {
						status.LastScanDate = occurrence.UpdateTime.AsTime()
					}
					break
				}
			}
		}

		statuses = append(statuses, status)
	}

	return statuses, aggErr
}

func buildGrafeasFilter(kind string, imageID ContainerImageIdentifier) string {
	resourceURL := fmt.Sprintf("https://%s/%s@%s", imageID.Registry, imageID.Repository, imageID.Hash)
	return fmt.Sprintf("kind=%q AND resourceUrl=%q", kind, resourceURL)
}

// Helper to normalize GCP severity to Kubescape expected severity
func normalizeGCPSeverity(severity grafeaspb.Severity) string {
	switch severity {
	case grafeaspb.Severity_CRITICAL:
		return "Critical"
	case grafeaspb.Severity_HIGH:
		return "High"
	case grafeaspb.Severity_MEDIUM:
		return "Medium"
	case grafeaspb.Severity_LOW:
		return "Low"
	case grafeaspb.Severity_MINIMAL:
		return "Negligible"
	default:
		return "Unknown"
	}
}

// GetImagesVulnerabilities retrieves the vulnerability reports for a list of image identifiers.
func (a *GCPAdaptor) GetImagesVulnerabilities(ctx context.Context, imageIDs []ContainerImageIdentifier) ([]ContainerImageVulnerabilityReport, error) {
	if a.client == nil {
		return nil, fmt.Errorf("gcp client not initialized, call login first")
	}

	var reports []ContainerImageVulnerabilityReport
	var aggErr error

	for _, imageID := range imageIDs {
		report := ContainerImageVulnerabilityReport{
			ImageID:         imageID,
			Vulnerabilities: []Vulnerability{},
		}

		if imageID.Hash == "" {
			reports = append(reports, report)
			continue
		}

		req := &grafeaspb.ListOccurrencesRequest{
			Parent:   fmt.Sprintf("projects/%s", a.projectID),
			Filter:   buildGrafeasFilter("VULNERABILITY", imageID),
			PageSize: 1000,
		}

		it := a.client.ListOccurrences(ctx, req)
		const maxVulns = 1000

		for {
			occurrence, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				fetchErr := fmt.Errorf("failed to query vulnerabilities for repository %s: %w", imageID.Repository, err)
				logger.L().Warning("skipping image vulnerabilities due to api error", helpers.Error(fetchErr))
				aggErr = errors.Join(aggErr, fetchErr)
				break
			}

			if len(report.Vulnerabilities) >= maxVulns {
				logger.L().Warning("truncated vulnerabilities", helpers.String("repository", imageID.Repository), helpers.Int("limit", maxVulns))
				break
			}

			if vulnDetails := occurrence.GetVulnerability(); vulnDetails != nil {
				id := vulnDetails.GetShortDescription()
				if id == "" && occurrence.GetNoteName() != "" {
					parts := strings.Split(occurrence.GetNoteName(), "/")
					id = parts[len(parts)-1]
				}

				vuln := Vulnerability{
					ID:          id,
					Severity:    normalizeGCPSeverity(vulnDetails.GetEffectiveSeverity()),
					Description: vulnDetails.GetLongDescription(),
					Links:       []string{},
				}

				for _, uri := range vulnDetails.GetRelatedUrls() {
					vuln.Links = append(vuln.Links, uri.GetUrl())
				}

				report.Vulnerabilities = append(report.Vulnerabilities, vuln)
			}
		}

		reports = append(reports, report)
	}

	return reports, aggErr
}

// GetImagesInformation retrieves the BOM and manifest information for a list of image identifiers.
func (a *GCPAdaptor) GetImagesInformation(ctx context.Context, imageIDs []ContainerImageIdentifier) ([]ContainerImageInformation, error) {
	if a.client == nil {
		return nil, fmt.Errorf("gcp client not initialized, call login first")
	}

	var infos []ContainerImageInformation

	for _, imageID := range imageIDs {
		info := ContainerImageInformation{
			ImageID: imageID,
			Bom:     []string{},
		}
		infos = append(infos, info)
	}

	return infos, nil
}

// Destroy cleans up any persistent resources used by the adaptor.
func (a *GCPAdaptor) Destroy() error {
	if a.owningClient != nil {
		err := a.owningClient.Close()
		a.owningClient = nil
		a.client = nil
		return err
	}
	return nil
}
