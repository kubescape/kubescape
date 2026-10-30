package imagescan

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

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

type gcpClientFactory func(ctx context.Context) (*containeranalysis.Client, error)
type gcpAPIFactory func(c *containeranalysis.Client) GCPAPI

// GCPAdaptor implements IContainerImageVulnerabilityAdaptor for Google Cloud Artifact Registry.
type GCPAdaptor struct {
	// Readers retain the client and project until their whole batch finishes;
	// lifecycle writers may then replace or close the owning connection.
	mu            sync.RWMutex
	client        GCPAPI
	owningClient  *containeranalysis.Client
	projectID     string
	clientFactory gcpClientFactory
	apiFactory    gcpAPIFactory
}

// NewGCPAdaptor creates a new GCP adaptor instance.
func NewGCPAdaptor() *GCPAdaptor {
	return &GCPAdaptor{
		clientFactory: func(ctx context.Context) (*containeranalysis.Client, error) {
			return containeranalysis.NewClient(ctx)
		},
		apiFactory: func(c *containeranalysis.Client) GCPAPI {
			return &gcpAPIWrapper{client: c.GetGrafeasClient()}
		},
	}
}

// setOwningClient installs c as the adaptor's owning containeranalysis
// client, closing any previously held client first. Without this, repeated
// Login calls on the same adaptor instance would leak the previous client's
// underlying gRPC connection pool. The caller must hold mu when the adaptor
// is shared with other goroutines.
func (a *GCPAdaptor) setOwningClient(c *containeranalysis.Client) {
	if a.owningClient != nil {
		if closeErr := a.owningClient.Close(); closeErr != nil {
			logger.L().Warning("failed to close previous gcp container analysis client", helpers.Error(closeErr))
		}
	}

	a.owningClient = c
	a.client = a.apiFactory(c)
}

// Login authenticates with GCP. It prioritizes the default application credentials.
// Explicit credentials passed via RegistryCredentials are intentionally unsupported
// as GCP SDK relies heavily on Workload Identity and Application Default Credentials.
func (a *GCPAdaptor) Login(ctx context.Context, registry string, credentials RegistryCredentials) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	// Drop the previous session before validating the new login, so a failed
	// re-login does not leave the previous project's client callable.
	a.client = nil
	if a.owningClient != nil {
		if err := a.owningClient.Close(); err != nil {
			return fmt.Errorf("failed to close previous container analysis client: %w", err)
		}
		a.owningClient = nil
	}

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

	c, err := a.clientFactory(ctx)
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
	if _, err := it.Next(); err != nil { // #nosec G104 -- iterator.Done is the expected end-of-iteration sentinel, not an error
		if err != iterator.Done {
			if a.owningClient != nil {
				if closeErr := a.owningClient.Close(); closeErr != nil {
					logger.L().Warning("failed to close gcp container analysis client after failed probe", helpers.Error(closeErr))
				}
			}
			a.owningClient = nil
			a.client = nil
			return fmt.Errorf("failed to authenticate or access gcp project %s: %w", a.projectID, err)
		}
		// iterator.Done means authentication succeeded but there are no occurrences yet.
	}

	return nil
}

// DescribeAdaptor provides a string description of the adaptor for help purposes.
func (a *GCPAdaptor) DescribeAdaptor() string {
	return "GCP Artifact Registry (GAR) Vulnerability Adaptor"
}

// GetImagesScanStatus retrieves the scan status for a list of image identifiers.
func (a *GCPAdaptor) GetImagesScanStatus(ctx context.Context, imageIDs []ContainerImageIdentifier) ([]ContainerImageScanStatus, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.client == nil {
		return nil, fmt.Errorf("gcp client not initialized, call login first")
	}

	return ProcessImages(imageIDs,
		func(imageID ContainerImageIdentifier) (ContainerImageScanStatus, error) {
			return a.getImageScanStatus(ctx, imageID)
		},
	)
}

func (a *GCPAdaptor) getImageScanStatus(ctx context.Context, imageID ContainerImageIdentifier) (ContainerImageScanStatus, error) {
	status := ContainerImageScanStatus{
		ImageID:         imageID,
		IsScanAvailable: false,
		IsBomAvailable:  false,
	}

	if imageID.Hash == "" {
		return status, nil
	}

	req := &grafeaspb.ListOccurrencesRequest{
		Parent: fmt.Sprintf("projects/%s", a.projectID),
		Filter: buildGrafeasFilter("DISCOVERY", imageID),
	}

	it := a.client.ListOccurrences(ctx, req)
	const maxScanStatusOccurrences = 1000
	seen := 0
	for {
		occurrence, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return status, fmt.Errorf("failed to query scan status for repository %s: %w", imageID.Repository, err)
		}
		if seen >= maxScanStatusOccurrences {
			return status, fmt.Errorf("scan status for repository %s is incomplete: exceeded the %d-occurrence limit", imageID.Repository, maxScanStatusOccurrences)
		}
		seen++

		mergeSuccessfulGCPScan(&status, occurrence)
	}

	return status, nil
}

// mergeSuccessfulGCPScan records a completed discovery occurrence without
// assuming that Grafeas returns occurrences in chronological order. An image
// may retain multiple discovery occurrences after rescans, so callers must
// inspect the complete bounded result set and keep the newest completion.
func mergeSuccessfulGCPScan(status *ContainerImageScanStatus, occurrence *grafeaspb.Occurrence) {
	if status == nil || occurrence == nil {
		return
	}

	discovery := occurrence.GetDiscovery()
	if discovery == nil || discovery.GetAnalysisStatus() != grafeaspb.DiscoveryOccurrence_FINISHED_SUCCESS {
		return
	}

	status.IsScanAvailable = true
	status.Status = ScanStatusScanned
	if occurrence.UpdateTime == nil || occurrence.UpdateTime.CheckValid() != nil {
		return
	}

	completedAt := occurrence.UpdateTime.AsTime()
	if completedAt.After(status.LastScanDate) {
		status.LastScanDate = completedAt
	}
}

func buildGrafeasFilter(kind string, imageID ContainerImageIdentifier) string {
	resourceURL := fmt.Sprintf("https://%s/%s@%s", imageID.Registry, imageID.Repository, imageID.Hash)
	return fmt.Sprintf("kind=%q AND resourceUrl=%q", kind, resourceURL)
}

// GetImagesVulnerabilities retrieves the vulnerability reports for a list of image identifiers.
func (a *GCPAdaptor) GetImagesVulnerabilities(ctx context.Context, imageIDs []ContainerImageIdentifier) ([]ContainerImageVulnerabilityReport, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.client == nil {
		return nil, fmt.Errorf("gcp client not initialized, call login first")
	}

	return ProcessImages(imageIDs,
		func(imageID ContainerImageIdentifier) (ContainerImageVulnerabilityReport, error) {
			report := ContainerImageVulnerabilityReport{
				ImageID:         imageID,
				Vulnerabilities: []Vulnerability{},
			}

			if imageID.Hash == "" {
				return report, nil
			}

			scanStatus, discoveryErr := a.getImageScanStatus(ctx, imageID)
			// Discovery status and vulnerability occurrences are independent
			// queries. Keep available findings when only discovery fails, while
			// still returning its error so callers cannot read an all-clear.
			if ctx.Err() != nil {
				return report, errors.Join(discoveryErr, ctx.Err())
			}

			if scanStatus.Status == ScanStatusScanned {
				report.Status = ScanStatusScanned
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
					return report, errors.Join(discoveryErr, fmt.Errorf("failed to query vulnerabilities for repository %s: %w", imageID.Repository, err))
				}

				if len(report.Vulnerabilities) >= maxVulns {
					return report, errors.Join(discoveryErr, fmt.Errorf("vulnerabilities for repository %s are incomplete: exceeded the %d-finding limit", imageID.Repository, maxVulns))
				}

				if vulnDetails := occurrence.GetVulnerability(); vulnDetails != nil {
					// The note identifies the advisory; ShortDescription is prose
					// and can be shared by several distinct vulnerabilities.
					id := vulnDetails.GetShortDescription()
					if occurrence.GetNoteName() != "" {
						parts := strings.Split(occurrence.GetNoteName(), "/")
						if noteID := parts[len(parts)-1]; noteID != "" {
							id = noteID
						}
					}

					vuln := Vulnerability{
						ID:          id,
						Severity:    NormalizeSeverity(vulnDetails.GetEffectiveSeverity().String()),
						Description: vulnDetails.GetLongDescription(),
						Links:       []string{},
					}

					for _, uri := range vulnDetails.GetRelatedUrls() {
						vuln.Links = append(vuln.Links, uri.GetUrl())
					}

					report.Vulnerabilities = append(report.Vulnerabilities, vuln)
				}
			}

			return report, discoveryErr
		},
	)
}

// GetImagesInformation retrieves the BOM and manifest information for a list of image identifiers.
func (a *GCPAdaptor) GetImagesInformation(ctx context.Context, imageIDs []ContainerImageIdentifier) ([]ContainerImageInformation, error) {
	a.mu.RLock()
	initialized := a.client != nil
	a.mu.RUnlock()
	if !initialized {
		return nil, fmt.Errorf("gcp client not initialized, call login first")
	}
	return FetchImagesInformation(imageIDs)
}

// Destroy cleans up any persistent resources used by the adaptor.
func (a *GCPAdaptor) Destroy() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.client = nil
	a.projectID = ""
	if a.owningClient != nil {
		err := a.owningClient.Close()
		a.owningClient = nil
		a.client = nil
		return err
	}
	return nil
}
