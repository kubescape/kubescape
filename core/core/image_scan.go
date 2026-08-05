package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/distribution/reference"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/kubescape/v3/core/cautils"
	ksmetav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
	"github.com/kubescape/kubescape/v3/core/pkg/resultshandling"
	"github.com/kubescape/kubescape/v3/pkg/imagescan"
)

// Data structure to represent attributes
type Attributes struct {
	Registry     string `json:"registry"`
	Organization string `json:"organization,omitempty"`
	ImageName    string `json:"imageName"`
	ImageTag     string `json:"imageTag,omitempty"`
}

// Data structure for a target
type Target struct {
	DesignatorType string     `json:"designatorType"`
	Attributes     Attributes `json:"attributes"`
}

// Data structure for metadata
type Metadata struct {
	Name string `json:"name"`
}

// Data structure for vulnerabilities and severities
type VulnerabilitiesIgnorePolicy struct {
	Metadata        Metadata `json:"metadata"`
	Kind            string   `json:"kind"`
	Targets         []Target `json:"targets"`
	Vulnerabilities []string `json:"vulnerabilities"`
	Severities      []string `json:"severities"`
}

// Loads exception policies from exceptions json object.
func GetImageExceptionsFromFile(filePath string) ([]VulnerabilitiesIgnorePolicy, error) {
	// Read the JSON file
	jsonFile, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading exceptions file: %w", err)
	}

	// Unmarshal the JSON data into an array of VulnerabilitiesIgnorePolicy
	var policies []VulnerabilitiesIgnorePolicy
	err = json.Unmarshal(jsonFile, &policies)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling exceptions file: %w", err)
	}

	return policies, nil
}

// This function will identify the registry, organization and image tag from the image name
func getAttributesFromImage(imgName string) (Attributes, error) {
	canonicalImageName, err := cautils.NormalizeImageName(imgName)
	if err != nil {
		return Attributes{}, err
	}

	// canonicalImageName is registry/[path/...]/name[:tag]. The registry is always
	// the first component, but the organization path in between is optional (a
	// registry image can have no organization) and may span multiple segments, so
	// don't assume a fixed three-token split. See #2391.
	tokens := strings.Split(canonicalImageName, "/")
	registry := tokens[0]

	organization := ""
	nameAndTag := tokens[len(tokens)-1]
	if len(tokens) > 2 {
		organization = strings.Join(tokens[1:len(tokens)-1], "/")
	}

	// nameAndTag may be "name", "name:tag", "name@algo:digest" (e.g.
	// "name@sha256:abc123..."), or "name:tag@algo:digest" - a digest-pinned
	// reference. Split off any "@digest" suffix first: the digest itself
	// contains a colon ("sha256:..."), so splitting nameAndTag on ":"
	// without accounting for that left "@sha256" stuck onto imageName and
	// the raw hash treated as the tag. Because regexStringMatch (below) is
	// an unanchored match, unanchored policy patterns (the common case,
	// e.g. "myimage") still matched the old broken ImageName; anchored
	// patterns (e.g. "^myimage$") did not, and this fixes those.
	beforeDigest := nameAndTag
	imageTag := "latest"
	if at := strings.Index(nameAndTag, "@"); at != -1 {
		beforeDigest = nameAndTag[:at]
		// No explicit tag on a digest-pinned reference: fall back to the
		// digest as ImageTag (deliberate choice, not Docker/OCI reference
		// semantics - Docker resolves a "name:tag@digest" reference by the
		// digest, ignoring the tag, but for *exception-policy matching* the
		// tag the user wrote is what they meant to target). This means an
		// exception policy that targets a specific ImageTag (e.g. "v3.*")
		// cannot match a purely digest-pinned scan, since ImageTag will be
		// the digest instead; only Registry/Organization/ImageName targets
		// (and an ImageTag target of "" - "any tag") can match it.
		imageTag = nameAndTag[at+1:]
	}

	imageName := beforeDigest
	if colon := strings.LastIndex(beforeDigest, ":"); colon != -1 {
		imageName = beforeDigest[:colon]
		imageTag = beforeDigest[colon+1:] // an explicit tag wins over the digest fallback above
	}

	attributes := Attributes{
		Registry:     registry,
		Organization: organization,
		ImageName:    imageName,
		ImageTag:     imageTag,
	}

	return attributes, nil
}

// Checks if the target string matches the regex pattern
func regexStringMatch(pattern, target string) bool {
	re, err := regexp.Compile(pattern)
	if err != nil {
		logger.L().StopError(fmt.Sprintf("Failed to generate regular expression: %s", err))
		return false
	}

	if re.MatchString(target) {
		return true
	}

	return false
}

// Compares the registry, organization, image name, image tag against the targets specified
// in the exception policy object to check if the image being scanned qualifies for an
// exception policy.
func isTargetImage(targets []Target, attributes Attributes) bool {
	for _, target := range targets {
		if regexStringMatch(target.Attributes.Registry, attributes.Registry) && regexStringMatch(target.Attributes.Organization, attributes.Organization) && regexStringMatch(target.Attributes.ImageName, attributes.ImageName) && regexStringMatch(target.Attributes.ImageTag, attributes.ImageTag) {
			return true
		}
	}

	return false
}

// Generates a list of unique CVE-IDs and the severities which are to be excluded for
// the image being scanned.
func getUniqueVulnerabilitiesAndSeverities(policies []VulnerabilitiesIgnorePolicy, image string) ([]string, []string) {
	// Create maps with slices as values to store unique vulnerabilities and severities (case-insensitive)
	uniqueVulns := make(map[string][]string)
	uniqueSevers := make(map[string][]string)

	imageAttributes, err := getAttributesFromImage(image)
	if err != nil {
		logger.L().StopError(fmt.Sprintf("Failed to generate image attributes: %s", err))
	}

	// Iterate over each policy and its vulnerabilities/severities
	for _, policy := range policies {
		// Include the exceptions only if the image is one of the targets
		if isTargetImage(policy.Targets, imageAttributes) {
			for _, vulnerability := range policy.Vulnerabilities {
				// grype's IgnoreRule matching is case-sensitive and advisory
				// sources do not share a single casing convention: CVE IDs
				// are uppercase, while GHSA IDs keep a lowercase suffix
				// (e.g. "GHSA-jc7w-c686-c4v9"). Emit the trimmed original
				// casing plus the uppercased and lowercased forms so users
				// can list the ID in any casing without the filter silently
				// missing the match (kubescape issue #1870).
				vulnerability = strings.TrimSpace(vulnerability)
				if vulnerability == "" {
					continue
				}
				uniqueVulns[vulnerability] = append(uniqueVulns[vulnerability], vulnerability)
				vulnerabilityUppercase := strings.ToUpper(vulnerability)
				if vulnerabilityUppercase != vulnerability {
					uniqueVulns[vulnerabilityUppercase] = append(uniqueVulns[vulnerabilityUppercase], vulnerability)
				}
				vulnerabilityLowercase := strings.ToLower(vulnerability)
				if vulnerabilityLowercase != vulnerability && vulnerabilityLowercase != vulnerabilityUppercase {
					uniqueVulns[vulnerabilityLowercase] = append(uniqueVulns[vulnerabilityLowercase], vulnerability)
				}
			}

			for _, severity := range policy.Severities {
				// Add to slice directly
				severityUppercase := strings.ToUpper(severity)
				uniqueSevers[severityUppercase] = append(uniqueSevers[severityUppercase], severity)
			}
		}
	}

	// Extract unique keys (which are unique vulnerabilities/severities) and their slices
	uniqueVulnsList := make([]string, 0, len(uniqueVulns))
	for vuln := range uniqueVulns {
		uniqueVulnsList = append(uniqueVulnsList, vuln)
	}

	uniqueSeversList := make([]string, 0, len(uniqueSevers))
	for sever := range uniqueSevers {
		uniqueSeversList = append(uniqueSeversList, sever)
	}

	return uniqueVulnsList, uniqueSeversList
}

// applyRegistryMapping replaces the registry part of the image name if a match
// is found in the provided mapping. The returned bool indicates whether a
// mapping key actually matched; callers should only retry when matched is true.
func applyRegistryMapping(imgName string, registryMapping map[string]string) (string, bool, error) {
	if len(registryMapping) == 0 {
		return imgName, false, nil
	}
	canonicalImageName, err := cautils.NormalizeImageName(imgName)
	if err != nil {
		return "", false, err
	}
	tokens := strings.Split(canonicalImageName, "/")
	registry := tokens[0]
	if altRegistry, ok := registryMapping[registry]; ok {
		tokens[0] = altRegistry
		mappedName := strings.Join(tokens, "/")
		if _, err := reference.ParseNormalizedNamed(mappedName); err != nil {
			return "", false, fmt.Errorf("invalid image reference after applying registry mapping: %w", err)
		}
		return mappedName, true, nil
	}
	return imgName, false, nil
}

// isResolutionError checks if the error is related to unreachable registry hosts
// (DNS resolution failures, connection refused, timeouts). It uses typed error
// checks first and falls back to substring matching for wrapped errors.
func isResolutionError(err error) bool {
	if err == nil {
		return false
	}

	// Typed error checks — stable across Go and library versions.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EHOSTUNREACH) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	// Belt-and-braces: substring fallback for deeply wrapped errors where
	// the typed original has been lost.
	errStr := err.Error()
	return strings.Contains(errStr, "no such host") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "i/o timeout")
}

// scanWithRegistryMapping attempts to scan an image and, on a resolution error,
// retries using a mapped registry if one is configured. It returns the scan
// results or a combined error preserving both the original and fallback context.
type imageScanService interface {
	Scan(context.Context, string, imagescan.RegistryCredentials, []string, []string) (*cautils.ImageScanData, error)
}

func scanWithRegistryMapping(
	ctx context.Context,
	svc imageScanService,
	img string,
	creds imagescan.RegistryCredentials,
	registryMapping map[string]string,
	vulnExceptions, sevExceptions []string,
) (*cautils.ImageScanData, error) {
	scanData, err := svc.Scan(ctx, img, creds, vulnExceptions, sevExceptions)
	if err == nil {
		return scanData, nil
	}

	if len(registryMapping) == 0 || !isResolutionError(err) {
		return nil, err
	}

	logger.L().Warning(fmt.Sprintf("Failed to scan image %s: %s. Trying registry mapping...", img, err))

	mappedImage, matched, mapErr := applyRegistryMapping(img, registryMapping)
	if mapErr != nil {
		return nil, fmt.Errorf("scan failed for %s (%w) and failed to construct mapped image: %w", img, err, mapErr)
	}
	if !matched {
		return nil, err
	}

	logger.L().Info(fmt.Sprintf("Scanning mapped image %s (original: %s)...", mappedImage, img))
	scanData, fallbackErr := svc.Scan(ctx, mappedImage, creds, vulnExceptions, sevExceptions)
	if fallbackErr != nil {
		return nil, fmt.Errorf("scan failed for %s (%w) and for mapped image %s: %w", img, err, mappedImage, fallbackErr)
	}
	return scanData, nil
}

func (ks *Kubescape) ScanImage(imgScanInfo *ksmetav1.ImageScanInfo, scanInfo *cautils.ScanInfo) (bool, error) {
	logger.L().Start(fmt.Sprintf("Scanning image %s...", imgScanInfo.Image))

	distCfg, installCfg, _, err := imagescan.NewDefaultDBConfig(scanInfo.ListingURL)
	if err != nil {
		logger.L().StopError(fmt.Sprintf("Invalid Grype database URL '%s': %v", scanInfo.ListingURL, err))
		return false, err
	}
	svc, err := imagescan.NewScanServiceWithMatchers(distCfg, installCfg, imgScanInfo.UseDefaultMatchers)
	if err != nil {
		logger.L().StopError(fmt.Sprintf("Failed to initialize image scanner: %s", err))
		return false, err
	}
	defer svc.Close()

	creds := imagescan.RegistryCredentials{
		Authority: imgScanInfo.Authority,
		Username:  imgScanInfo.Username,
		Password:  imgScanInfo.Password,
		Token:     imgScanInfo.Token,
	}

	var vulnerabilityExceptions []string
	var severityExceptions []string
	if imgScanInfo.Exceptions != "" {
		exceptionPolicies, err := GetImageExceptionsFromFile(imgScanInfo.Exceptions)
		if err != nil {
			logger.L().StopError(fmt.Sprintf("Failed to load exceptions from file: %s", imgScanInfo.Exceptions))
			return false, err
		}

		vulnerabilityExceptions, severityExceptions = getUniqueVulnerabilitiesAndSeverities(exceptionPolicies, imgScanInfo.Image)
	}

	imageScanData, err := scanWithRegistryMapping(
		ks.Context(), svc, imgScanInfo.Image, creds,
		scanInfo.RegistryMapping, vulnerabilityExceptions, severityExceptions,
	)
	if err != nil {
		logger.L().StopError(fmt.Sprintf("Failed to scan image %s: %s", imgScanInfo.Image, err))
		return false, err
	}

	logger.L().StopSuccess(fmt.Sprintf("Successfully scanned image: %s", imgScanInfo.Image))

	scanInfo.SetScanType(cautils.ScanTypeImage)

	outputPrinters, err := GetOutputPrinters(scanInfo, ks.Context(), "")
	if err != nil {
		return false, err
	}

	uiPrinter := GetUIPrinter(ks.Context(), scanInfo, "")

	resultsHandler := resultshandling.NewResultsHandler(nil, outputPrinters, uiPrinter)

	resultsHandler.ImageScanData = []cautils.ImageScanData{*imageScanData}

	return svc.ExceedsSeverityThreshold(imagescan.ParseSeverity(scanInfo.FailThresholdSeverity), imageScanData.Matches), resultsHandler.HandleResults(ks.Context(), scanInfo)
}

// ScanErrorCategory defines distinct vulnerability scan failure categories.
type ScanErrorCategory string

const (
	ErrCategoryDNSTimeout  ScanErrorCategory = "Registry DNSTimeout/Unreachable"
	ErrCategoryCredentials ScanErrorCategory = "Registry Credentials/Authentication"
	ErrCategoryParser      ScanErrorCategory = "Image Manifest/Parser Issue"
	ErrCategoryGeneral     ScanErrorCategory = "General Error"
)

// CategorizeScanError inspects an error and assigns a ScanErrorCategory.
func CategorizeScanError(err error) ScanErrorCategory {
	if err == nil {
		return ""
	}
	if isResolutionError(err) {
		return ErrCategoryDNSTimeout
	}
	errStr := strings.ToLower(err.Error())
	if strings.Contains(errStr, "unauthorized") ||
		strings.Contains(errStr, "authentication required") ||
		strings.Contains(errStr, "forbidden") ||
		strings.Contains(errStr, "401") ||
		strings.Contains(errStr, "403") ||
		strings.Contains(errStr, "credentials") ||
		strings.Contains(errStr, "login") ||
		strings.Contains(errStr, "auth") {
		return ErrCategoryCredentials
	}
	if strings.Contains(errStr, "manifest") ||
		strings.Contains(errStr, "parse") ||
		strings.Contains(errStr, "syntax") ||
		strings.Contains(errStr, "unmarshal") ||
		strings.Contains(errStr, "decode") ||
		strings.Contains(errStr, "unknown format") ||
		strings.Contains(errStr, "invalid") ||
		strings.Contains(errStr, "malformed") {
		return ErrCategoryParser
	}
	return ErrCategoryGeneral
}

// CategorizedScanError groups an error with its target image and classification.
type CategorizedScanError struct {
	Image    string
	Category ScanErrorCategory
	Err      error
}

// ScanErrorAggregator collects and aggregates categorized errors across concurrent worker scans.
type ScanErrorAggregator struct {
	mu     sync.Mutex
	Errors []CategorizedScanError
}

// NewScanErrorAggregator creates a new thread-safe error aggregator.
func NewScanErrorAggregator() *ScanErrorAggregator {
	return &ScanErrorAggregator{
		Errors: make([]CategorizedScanError, 0),
	}
}

// Add appends a categorized error to the aggregator.
func (a *ScanErrorAggregator) Add(image string, err error) {
	if err == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Errors = append(a.Errors, CategorizedScanError{
		Image:    image,
		Category: CategorizeScanError(err),
		Err:      err,
	})
}

// Summary returns the tally of errors grouped by category.
func (a *ScanErrorAggregator) Summary() map[ScanErrorCategory]int {
	a.mu.Lock()
	defer a.mu.Unlock()
	summary := make(map[ScanErrorCategory]int)
	for _, e := range a.Errors {
		summary[e.Category]++
	}
	return summary
}

// HasErrors indicates whether any scan errors occurred.
func (a *ScanErrorAggregator) HasErrors() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.Errors) > 0
}

// Error formats the aggregated scan errors as a multiline string.
func (a *ScanErrorAggregator) Error() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.Errors) == 0 {
		return ""
	}
	summary := make(map[ScanErrorCategory][]string)
	for _, e := range a.Errors {
		summary[e.Category] = append(summary[e.Category], fmt.Sprintf("%s (%v)", e.Image, e.Err))
	}
	var b strings.Builder
	b.WriteString("Aggregated image scan errors:\n")
	for cat, list := range summary {
		b.WriteString(fmt.Sprintf("[%s]: %d errors\n", cat, len(list)))
		for _, msg := range list {
			b.WriteString(fmt.Sprintf("  - %s\n", msg))
		}
	}
	return b.String()
}

// RegistryThrottler manages concurrency limits and pull pacing per registry host.
type RegistryThrottler struct {
	mu          sync.Mutex
	semaphores  map[string]chan struct{}
	lastCall    map[string]time.Time
	maxConcur   int
	minInterval time.Duration
}

// NewRegistryThrottler instantiates a per-registry pull rate limiter and concurrency gate.
func NewRegistryThrottler(maxConcurrencyPerRegistry int, minInterval time.Duration) *RegistryThrottler {
	if maxConcurrencyPerRegistry <= 0 {
		maxConcurrencyPerRegistry = 2
	}
	return &RegistryThrottler{
		semaphores:  make(map[string]chan struct{}),
		lastCall:    make(map[string]time.Time),
		maxConcur:   maxConcurrencyPerRegistry,
		minInterval: minInterval,
	}
}

func (rt *RegistryThrottler) getRegistryDomain(imgName string) string {
	canonical, err := cautils.NormalizeImageName(imgName)
	if err != nil {
		parts := strings.Split(imgName, "/")
		if len(parts) > 0 && (strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") || parts[0] == "localhost") {
			return parts[0]
		}
		return "docker.io"
	}
	parts := strings.Split(canonical, "/")
	if len(parts) > 0 {
		return parts[0]
	}
	return "docker.io"
}

// Acquire requests execution permission for pulling/scanning an image against its target registry.
func (rt *RegistryThrottler) Acquire(ctx context.Context, imgName string) error {
	reg := rt.getRegistryDomain(imgName)
	rt.mu.Lock()
	sem, ok := rt.semaphores[reg]
	if !ok {
		sem = make(chan struct{}, rt.maxConcur)
		rt.semaphores[reg] = sem
	}
	last, existed := rt.lastCall[reg]
	now := time.Now()
	var waitDuration time.Duration
	if existed && rt.minInterval > 0 {
		elapsed := now.Sub(last)
		if elapsed < rt.minInterval {
			waitDuration = rt.minInterval - elapsed
			rt.lastCall[reg] = last.Add(rt.minInterval)
		} else {
			rt.lastCall[reg] = now
		}
	} else {
		rt.lastCall[reg] = now
	}
	rt.mu.Unlock()

	if waitDuration > 0 {
		timer := time.NewTimer(waitDuration)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case sem <- struct{}{}:
		return nil
	}
}

// Release yields the throttling slot back to the registry domain pool.
func (rt *RegistryThrottler) Release(imgName string) {
	reg := rt.getRegistryDomain(imgName)
	rt.mu.Lock()
	sem, ok := rt.semaphores[reg]
	rt.mu.Unlock()
	if ok {
		select {
		case <-sem:
		default:
		}
	}
}

// LayerScanResult stores packages and vulnerability matches associated with a specific base layer.
type LayerScanResult struct {
	LayerDigest string
	Packages    []pkg.Package
	Matches     match.Matches
}

// LayerDeduplicator maintains a thread-safe cache of already fetched and analyzed shared base layers.
type LayerDeduplicator struct {
	mu         sync.RWMutex
	layerCache map[string]*LayerScanResult
	hits       uint64
	misses     uint64
}

// NewLayerDeduplicator initializes a new layer deduplication cache.
func NewLayerDeduplicator() *LayerDeduplicator {
	return &LayerDeduplicator{
		layerCache: make(map[string]*LayerScanResult),
	}
}

// Get checks if a layer's analysis findings are already cached.
func (d *LayerDeduplicator) Get(layerDigest string) (*LayerScanResult, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	res, ok := d.layerCache[layerDigest]
	if ok {
		d.hits++
		return res, true
	}
	d.misses++
	return nil, false
}

// Put records analyzed packages and vulnerability matches under a layer digest.
func (d *LayerDeduplicator) Put(layerDigest string, res *LayerScanResult) {
	if layerDigest == "" || res == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.layerCache[layerDigest] = res
}

// PutIfAbsent records findings under a layer digest if not already present, without incrementing misses.
func (d *LayerDeduplicator) PutIfAbsent(layerDigest string, res *LayerScanResult) {
	if layerDigest == "" || res == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, exists := d.layerCache[layerDigest]; !exists {
		d.layerCache[layerDigest] = res
	}
}

// Stats returns cache hit/miss statistics and current cached layer count.
func (d *LayerDeduplicator) Stats() (hits, misses uint64, cachedLayers int) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.hits, d.misses, len(d.layerCache)
}

// LayerGetterFunc defines a callback function to resolve base layer digests of an image.
type LayerGetterFunc func(ctx context.Context, image string, creds imagescan.RegistryCredentials) ([]string, error)

// DeduplicatingImageScanService decorates an image scan service with layer caching and pull throttling.
type DeduplicatingImageScanService struct {
	delegate    imageScanService
	dedup       *LayerDeduplicator
	throttler   *RegistryThrottler
	layerGetter LayerGetterFunc
}

// NewDeduplicatingImageScanService constructs a deduplicating image scan service.
func NewDeduplicatingImageScanService(delegate imageScanService, dedup *LayerDeduplicator, throttler *RegistryThrottler, layerGetter LayerGetterFunc) *DeduplicatingImageScanService {
	return &DeduplicatingImageScanService{
		delegate:    delegate,
		dedup:       dedup,
		throttler:   throttler,
		layerGetter: layerGetter,
	}
}

func (d *DeduplicatingImageScanService) Scan(ctx context.Context, img string, creds imagescan.RegistryCredentials, vulnExceptions, sevExceptions []string) (*cautils.ImageScanData, error) {
	if d.throttler != nil {
		if err := d.throttler.Acquire(ctx, img); err != nil {
			return nil, err
		}
		defer d.throttler.Release(img)
	}

	var layers []string
	if d.layerGetter != nil {
		var err error
		layers, err = d.layerGetter(ctx, img, creds)
		if err != nil {
			logger.L().Ctx(ctx).Debug(fmt.Sprintf("Could not fetch layer digests for %s: %v", img, err))
		}
	}

	if len(layers) > 0 && d.dedup != nil {
		allCached := true
		cachedMatches := match.NewMatches()
		var cachedPkgs []pkg.Package
		seenPkgs := make(map[string]bool)

		for _, layer := range layers {
			res, ok := d.dedup.Get(layer)
			if !ok {
				allCached = false
				break
			}
			for _, p := range res.Packages {
				key := fmt.Sprintf("%s:%s", p.Name, p.Version)
				if !seenPkgs[key] {
					seenPkgs[key] = true
					cachedPkgs = append(cachedPkgs, p)
				}
			}
			for m := range res.Matches.Enumerate() {
				cachedMatches.Add(m)
			}
		}

		if allCached {
			logger.L().Ctx(ctx).Debug(fmt.Sprintf("Layer deduplication hit for image %s: skipping full scan", img))
			return &cautils.ImageScanData{
				Image:   img,
				Matches: cachedMatches,
				Packages: cachedPkgs,
			}, nil
		}
	}

	scanData, err := d.delegate.Scan(ctx, img, creds, vulnExceptions, sevExceptions)
	if err != nil {
		return nil, err
	}

	if len(layers) > 0 && d.dedup != nil && scanData != nil {
		for _, layer := range layers {
			d.dedup.PutIfAbsent(layer, &LayerScanResult{
				LayerDigest: layer,
				Packages:    scanData.Packages,
				Matches:     scanData.Matches,
			})
		}
	}

	return scanData, nil
}

// ImageScanJob represents an item of work for the concurrent scanner.
type ImageScanJob struct {
	Image                   string
	RegistryCredentials     imagescan.RegistryCredentials
	VulnerabilityExceptions []string
	SeverityExceptions      []string
	RegistryMapping         map[string]string
}

// ImageScanResult conveys the scan output and categorized errors from a worker.
type ImageScanResult struct {
	Image    string
	ScanData *cautils.ImageScanData
	Error    error
}

// ImageScanOrchestrator coordinates concurrent image scan execution across a worker pool.
type ImageScanOrchestrator struct {
	concurrency     int
	svc             imageScanService
	errorAggregator *ScanErrorAggregator
}

// NewImageScanOrchestrator instantiates an orchestrator with a worker pool size.
func NewImageScanOrchestrator(svc imageScanService, concurrency int) *ImageScanOrchestrator {
	if concurrency <= 0 {
		concurrency = 5
	}
	return &ImageScanOrchestrator{
		concurrency:     concurrency,
		svc:             svc,
		errorAggregator: NewScanErrorAggregator(),
	}
}

// ScanImages processes multiple image scanning jobs concurrently using the worker pool.
func (o *ImageScanOrchestrator) ScanImages(ctx context.Context, jobs []ImageScanJob) []ImageScanResult {
	if len(jobs) == 0 {
		return nil
	}

	jobChan := make(chan ImageScanJob, len(jobs))
	resultChan := make(chan ImageScanResult, len(jobs))

	for _, job := range jobs {
		jobChan <- job
	}
	close(jobChan)

	var wg sync.WaitGroup
	workers := o.concurrency
	if workers > len(jobs) {
		workers = len(jobs)
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobChan {
				select {
				case <-ctx.Done():
					resultChan <- ImageScanResult{
						Image: job.Image,
						Error: fmt.Errorf("scan canceled: %w", ctx.Err()),
					}
					return
				default:
				}

				scanData, err := scanWithRegistryMapping(
					ctx, o.svc, job.Image, job.RegistryCredentials,
					job.RegistryMapping, job.VulnerabilityExceptions, job.SeverityExceptions,
				)
				if err != nil {
					if o.errorAggregator != nil {
						o.errorAggregator.Add(job.Image, err)
					}
				}
				resultChan <- ImageScanResult{
					Image:    job.Image,
					ScanData: scanData,
					Error:    err,
				}
			}
		}()
	}

	wg.Wait()
	close(resultChan)

	results := make([]ImageScanResult, 0, len(jobs))
	for res := range resultChan {
		results = append(results, res)
	}
	return results
}

// GetErrorAggregator returns the orchestrator's scan error aggregator.
func (o *ImageScanOrchestrator) GetErrorAggregator() *ScanErrorAggregator {
	return o.errorAggregator
}
