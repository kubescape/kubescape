package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/armosec/utils-go/boolutils"
	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	"github.com/kubescape/kubescape/v3/core/core"
	"github.com/kubescape/kubescape/v3/httphandler/config"
	"github.com/kubescape/kubescape/v3/httphandler/storage"
	utilsapisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var scanImpl = scan // Override for testing
func (handler *HTTPHandler) executeScan(scanReq *scanRequestParams) {
	response := &utilsmetav1.Response{}

	defer func() {
		if r := recover(); r != nil {
			err := fmt.Errorf("scan panicked: %v", r)
			logger.L().Ctx(scanReq.ctx).Error("scan panic recovered", helpers.String("ID", scanReq.scanID), helpers.Error(err))
			responseMsg := err.Error()
			if persistErr := writeScanErrorToFile(err, scanReq.scanID); persistErr != nil {
				logger.L().Ctx(scanReq.ctx).Error("failed to persist panic error to file", helpers.String("ID", scanReq.scanID), helpers.Error(persistErr))
				responseMsg = persistErr.Error()
			}
			handler.state.setNotBusy(scanReq.scanID)
			if scanReq.scanQueryParams.ReturnResults {
				response.Type = utilsapisv1.ErrorScanResponseType
				response.Response = responseMsg
				select {
				case scanReq.resp <- response:
				default:
				}
			}
		}
	}()

	logger.L().Info("scan triggered", helpers.String("ID", scanReq.scanID))
	_, err := scanImpl(scanReq.ctx, scanReq.scanInfo, scanReq.scanID, scanReq.scanQueryParams.SkipPersistence)
	if err != nil {
		logger.L().Ctx(scanReq.ctx).Error("scanning failed", helpers.String("ID", scanReq.scanID), helpers.Error(err))
		if scanReq.scanQueryParams.ReturnResults {
			response.Type = utilsapisv1.ErrorScanResponseType
			response.Response = err.Error()
		}
	} else {
		logger.L().Ctx(scanReq.ctx).Success("done scanning", helpers.String("ID", scanReq.scanID))
		if scanReq.scanQueryParams.ReturnResults {
			response.Type = utilsapisv1.ResultsV1ScanResponseType
		}
	}

	handler.state.setNotBusy(scanReq.scanID)

	// return results, if someone's waiting for them; never block.
	select {
	case scanReq.resp <- response:
	default:
	}

	if scanReq.callbackURL != "" {
		payload := scanCallbackPayload{ID: scanReq.scanID, Status: callbackStatusCompleted}
		if err != nil {
			payload.Status = callbackStatusFailed
			payload.Error = "scan failed"
		}
		cbCtx := context.WithoutCancel(scanReq.ctx)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logger.L().Ctx(cbCtx).Error("scan completion callback panicked", helpers.String("ID", scanReq.scanID), helpers.Error(fmt.Errorf("%v", r)))
				}
			}()
			if cbErr := postScanCallback(cbCtx, scanReq.callbackURL, payload); cbErr != nil {
				logger.L().Ctx(cbCtx).Error("failed to deliver scan completion callback", helpers.String("ID", scanReq.scanID), helpers.Error(cbErr))
			}
		}()
	}
}

// executeScan execute the scan request passed in the channel
func (handler *HTTPHandler) watchForScan() {
	for {
		scanReq := <-handler.scanRequestChan
		logger.L().Info("triggering scan", helpers.String("scanID", scanReq.scanID))
		handler.executeScan(scanReq)
	}
}
func scan(ctx context.Context, scanInfo *cautils.ScanInfo, scanID string, skipPersistence bool) (*reporthandlingv2.PostureReport, error) {
	ctx, spanScan := otel.Tracer("").Start(ctx, "kubescape.scan")
	defer spanScan.End()

	ks := core.NewKubescape(ctx)

	spanScan.AddEvent("scanning metadata",
		trace.WithAttributes(attribute.String("version", versioncheck.BuildNumber)),
		trace.WithAttributes(attribute.String("build", versioncheck.Client)),
		trace.WithAttributes(attribute.String("scanID", scanInfo.ScanID)),
		trace.WithAttributes(attribute.Bool("scanAll", scanInfo.ScanAll)),
		trace.WithAttributes(attribute.Bool("HostSensorEnabled", scanInfo.HostSensorEnabled.GetBool())),
		trace.WithAttributes(attribute.String("excludedNamespaces", scanInfo.ExcludedNamespaces)),
		trace.WithAttributes(attribute.String("includeNamespaces", scanInfo.IncludeNamespaces)),
		trace.WithAttributes(attribute.String("hostSensorYamlPath", scanInfo.HostSensorYamlPath)),
	)

	result, err := ks.Scan(scanInfo)
	if err != nil {
		return nil, writeScanErrorToFile(err, scanID)
	}
	if err := result.HandleResults(ctx, scanInfo); err != nil {
		return nil, writeScanErrorToFile(err, scanID)
	}

	if !skipPersistence {
		store := storage.GetStorage()
		// do not store results locally when we are sending them
		if store != nil && config.GetAccount() == "" {
			pr := result.GetResults()

			// StorePostureReportResults persists to the operator storage backend
			// (CRD/ConfigMap). This runs after HandleResults has already written
			// the valid JSON to OutputDir, so a failure here is a persistence
			// problem, not a scan failure. Log it and let the poller read the
			// valid result rather than overwriting it with a failed artifact.
			if err := store.StorePostureReportResults(ctx, pr); err != nil {
				logger.L().Ctx(ctx).Error("failed to persist scan results to storage", helpers.String("scanID", scanID), helpers.Error(err))
			}
		} else {
			logger.L().Debug("storage is not initialized - skipping storing results")
		}
	} else {
		logger.L().Info("skipPersistence=true, skipping storing results")
	}

	return nil, nil
}

// ScanFailedError carries the plaintext error written by writeScanErrorToFile.
// readResultsFile returns this when the only artifact for a scan ID is under
// FailedOutputDir, so the Results handler can surface the real scan failure
// instead of a JSON parse error.
type ScanFailedError struct {
	Message string
}

func (e *ScanFailedError) Error() string {
	return e.Message
}

func readResultsFile(fileID string) (*reporthandlingv2.PostureReport, error) {
	parsedUUID, err := uuid.Parse(fileID)
	if err != nil {
		logger.L().Warning("invalid scan ID requested", helpers.String("ID", fileID), helpers.Error(err))
		return nil, fmt.Errorf("invalid scan ID format")
	}
	cleanID := parsedUUID.String()

	extensions := []string{"", ".json"}

	// Failed artifacts win over success artifacts. HandleResults writes the
	// JSON output before later failure points (e.g. StorePostureReportResults),
	// so when both files exist the failed one is the source of truth and the
	// success file is stale data that must not mask the failure.
	for _, ext := range extensions {
		path := filepath.Join(FailedOutputDir, cleanID+ext)
		f, err := os.ReadFile(path)
		if err == nil {
			return nil, &ScanFailedError{Message: string(f)}
		}
	}

	for _, ext := range extensions {
		path := filepath.Join(OutputDir, cleanID+ext)
		f, err := os.ReadFile(path)
		if err == nil {
			postureReport := &reporthandlingv2.PostureReport{}
			err = json.Unmarshal(f, postureReport)
			return postureReport, err
		}
	}

	return nil, fmt.Errorf("file %s not found", cleanID)
}

func removeResultDirs() {
	if err := os.RemoveAll(OutputDir); err != nil {
		logger.L().Error("failed to remove output directory", helpers.String("path", OutputDir), helpers.Error(err))
	}
	if err := os.RemoveAll(FailedOutputDir); err != nil {
		logger.L().Error("failed to remove failed output directory", helpers.String("path", FailedOutputDir), helpers.Error(err))
	}
}

func removeResultsFile(fileID string) error {
	parsedUUID, err := uuid.Parse(fileID)
	if err != nil {
		logger.L().Warning("invalid scan ID requested", helpers.String("ID", fileID), helpers.Error(err))
		return nil // Invalid ID means no file to delete
	}
	cleanID := parsedUUID.String()

	dirs := []string{OutputDir, FailedOutputDir}
	extensions := []string{"", ".json"}

	for _, dir := range dirs {
		for _, ext := range extensions {
			path := filepath.Join(dir, cleanID+ext)
			err := os.Remove(path)
			if err != nil && !os.IsNotExist(err) {
				logger.L().Warning("failed to remove result file", helpers.String("path", path), helpers.Error(err))
			}
		}
	}
	return nil
}

func getScanCommand(scanRequest *utilsmetav1.PostScanRequest, scanID string) *cautils.ScanInfo {

	scanInfo := ToScanInfo(scanRequest)
	scanInfo.ScanID = scanID

	// *** start ***
	// Set default format
	if scanInfo.Format == "" {
		scanInfo.Format = "json"
	}
	scanInfo.FormatVersion = "v2" // latest version
	// *** end ***

	// *** start ***
	// DO NOT CHANGE
	scanInfo.Output = filepath.Join(OutputDir, scanID)
	// *** end ***

	return scanInfo
}

func defaultScanInfo() *cautils.ScanInfo {
	scanInfo := &cautils.ScanInfo{}
	scanInfo.FailThreshold = 100
	scanInfo.ComplianceThreshold = 0
	scanInfo.AccountID = envToString("KS_ACCOUNT_ID", config.GetAccount())   // publish results to Kubescape SaaS
	scanInfo.AccessKey = envToString("KS_ACCESS_KEY", config.GetAccessKey()) // publish results to Kubescape SaaS
	scanInfo.ExcludedNamespaces = envToString("KS_EXCLUDE_NAMESPACES", "")   // namespaces to exclude
	scanInfo.IncludeNamespaces = envToString("KS_INCLUDE_NAMESPACES", "")    // namespaces to include
	scanInfo.HostSensorYamlPath = envToString("KS_HOST_SCAN_YAML", "")       // path to host scan YAML
	scanInfo.FormatVersion = envToString("KS_FORMAT_VERSION", "v2")          // output format version
	scanInfo.Format = envToString("KS_FORMAT", "json")                       // default output should be json
	scanInfo.Submit = envToBool("KS_SUBMIT", false)                          // publish results to Kubescape SaaS
	scanInfo.Local = envToBool("KS_KEEP_LOCAL", false)                       // do not publish results to Kubescape SaaS
	scanInfo.EnableRegoPrint = envToBool("KS_REGO_PRINT", false)             // print rego rules
	// Only set HostSensorEnabled when explicitly configured; leaving it nil allows
	// auto-detection of node-agent CRDs in getHostSensorHandler.
	if val, ok := os.LookupEnv("KS_ENABLE_HOST_SCANNER"); ok {
		scanInfo.HostSensorEnabled.SetBool(boolutils.StringToBool(val))
	}
	if !envToBool("KS_DOWNLOAD_ARTIFACTS", false) {
		scanInfo.UseArtifactsFrom = getter.DefaultLocalStore // Load files from cache (this will prevent kubescape fom downloading the artifacts every time)
	}

	return scanInfo
}

func envToBool(env string, defaultValue bool) bool {
	if d, ok := os.LookupEnv(env); ok {
		return boolutils.StringToBool(d)
	}
	return defaultValue
}

func envToString(env string, defaultValue string) string {
	if d, ok := os.LookupEnv(env); ok {
		return d
	}
	return defaultValue
}

func writeScanErrorToFile(err error, scanID string) (e error) {
	if e = os.MkdirAll(FailedOutputDir, os.ModePerm); e != nil {
		return fmt.Errorf("failed to scan. reason: '%s'. failed to save error in file - failed to create directory. reason: %s", err.Error(), e.Error())
	}
	var f *os.File
	f, e = os.Create(filepath.Join(FailedOutputDir, scanID))
	if e != nil {
		return fmt.Errorf("failed to scan. reason: '%s'. failed to save error in file - failed to open file for writing. reason: %s", err.Error(), e.Error())
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			e = fmt.Errorf("%w; failed to close scan error file: %w", e, cerr)
		}
	}()

	if _, e = f.Write([]byte(err.Error())); e != nil {
		return fmt.Errorf("failed to scan. reason: '%s'. failed to save error in file - failed to write. reason: %s", err.Error(), e.Error())
	}
	return fmt.Errorf("failed to scan. reason: '%s'", err.Error())
}

// responseToBytes convert response object to bytes
func responseToBytes(res *utilsmetav1.Response) []byte {
	b, _ := json.Marshal(res)
	return b
}

const (
	callbackStatusCompleted = "completed"
	callbackStatusFailed    = "failed"

	// callbackAllowlistEnv, when set, is an authoritative comma-separated list of
	// CIDRs (or bare IPs) the resolved callback host must fall within.
	callbackAllowlistEnv = "KS_CALLBACK_ALLOWED_CIDRS"
	// callbackEnabledEnv opts callbacks in when no allowlist is configured;
	// without either, callbacks are disabled so the server cannot be used as an
	// arbitrary outbound-request emitter.
	callbackEnabledEnv = "KS_CALLBACK_ENABLED"

	callbackRequestTimeout = 5 * time.Second
	callbackWallTime       = 20 * time.Second
	callbackBackoff        = 2 * time.Second
	callbackMaxAttempts    = 3
)

// scanCallbackPayload is the completion signal POSTed to a caller-supplied
// callback URL. It is intentionally a signal only - it carries the scan ID, not
// the PostureReport, and receivers must GET /v1/results for the data. Delivery
// is at-least-once and best-effort with no durability across server restarts,
// so receivers must dedup on ID and keep a poll/reconcile fallback.
type scanCallbackPayload struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// ipResolver is the subset of net.Resolver used for callback host screening;
// it is a package var so tests can simulate DNS responses.
type ipResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// callbackResolver is the resolver used for callback host screening; it is a
// package var so tests can simulate DNS responses.
var callbackResolver ipResolver = net.DefaultResolver

// callbackEnabled reports whether scan-completion callbacks are turned on,
// either explicitly via KS_CALLBACK_ENABLED or implicitly by configuring an
// allowlist.
func callbackEnabled() bool {
	return envToString(callbackAllowlistEnv, "") != "" || boolutils.StringToBool(envToString(callbackEnabledEnv, ""))
}

// validateCallbackURL enforces the parse-time callback contract: callbacks must
// be enabled, and the URL must be http/https with no embedded credentials.
// Network-level SSRF screening happens later, at dial time, in postScanCallback.
func validateCallbackURL(rawURL string) (*url.URL, error) {
	if !callbackEnabled() {
		return nil, fmt.Errorf("scan completion callbacks are disabled; set %s=true or configure %s", callbackEnabledEnv, callbackAllowlistEnv)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid callback URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("callback URL scheme must be http or https")
	}
	if u.User != nil {
		return nil, fmt.Errorf("callback URL must not contain userinfo")
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("callback URL must contain a host")
	}
	return u, nil
}

// postScanCallback delivers payload to rawURL, screening and pinning the
// resolved IP against SSRF and retrying transport and 5xx failures within a
// bounded wall-time deadline.
func postScanCallback(ctx context.Context, rawURL string, payload scanCallbackPayload) error {
	u, err := validateCallbackURL(rawURL)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, callbackWallTime)
	defer cancel()

	// Resolve and screen once, then dial that exact IP, so the address vetted
	// here is the address connected to - closing the DNS-rebinding window.
	ip, err := screenCallbackHost(ctx, u.Hostname())
	if err != nil {
		return err
	}

	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	pinnedAddr := net.JoinHostPort(ip.String(), port)

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	client := &http.Client{
		Timeout: callbackRequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: callbackRequestTimeout}).DialContext(ctx, network, pinnedAddr)
			},
		},
	}

	var lastErr error
	for attempt := 0; attempt < callbackMaxAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("callback delivery deadline exceeded: %w", ctx.Err())
			case <-time.After(callbackBackoff * time.Duration(attempt)):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("callback endpoint returned status %d", resp.StatusCode)
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return lastErr
		}
	}
	return lastErr
}

// screenCallbackHost resolves host and returns one IP that is permitted to be
// dialed. When callbackAllowlistEnv is set it is authoritative (the IP must fall
// inside it); otherwise loopback, link-local, private and other non-routable
// ranges are denied.
func screenCallbackHost(ctx context.Context, host string) (net.IP, error) {
	allowlist, err := callbackAllowlist()
	if err != nil {
		return nil, err
	}

	var candidates []net.IP
	if literal := net.ParseIP(host); literal != nil {
		candidates = []net.IP{literal}
	} else {
		addrs, err := callbackResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve callback host: %w", err)
		}
		for i := range addrs {
			candidates = append(candidates, addrs[i].IP)
		}
	}

	for _, ip := range candidates {
		if len(allowlist) > 0 {
			if allowlistContains(allowlist, ip) {
				return ip, nil
			}
			continue
		}
		if !isBlockedCallbackIP(ip) {
			return ip, nil
		}
	}

	if len(allowlist) > 0 {
		return nil, fmt.Errorf("callback host is not within the configured allowlist")
	}
	return nil, fmt.Errorf("callback host resolves to a disallowed (loopback, link-local or private) address")
}

// extraBlockedCallbackCIDRs are non-routable ranges with no net.IP predicate:
// CGNAT, the "this host" block, and the IPv4 limited broadcast address.
var extraBlockedCallbackCIDRs = func() []*net.IPNet {
	nets := make([]*net.IPNet, 0, 3)
	for _, c := range []string{"100.64.0.0/10", "0.0.0.0/8", "255.255.255.255/32"} {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}()

// isBlockedCallbackIP reports whether ip falls in a loopback, link-local,
// private, or otherwise non-routable range that must never be dialed by default.
func isBlockedCallbackIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() ||
		ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	for _, n := range extraBlockedCallbackCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// callbackAllowlist parses callbackAllowlistEnv into networks; bare IPs are
// treated as single-host CIDRs. It returns nil when the env var is unset.
func callbackAllowlist() ([]*net.IPNet, error) {
	raw := envToString(callbackAllowlistEnv, "")
	if raw == "" {
		return nil, nil
	}
	var nets []*net.IPNet
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") {
			if ip := net.ParseIP(entry); ip != nil && ip.To4() != nil {
				entry += "/32"
			} else {
				entry += "/128"
			}
		}
		_, n, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid %s entry %q: %w", callbackAllowlistEnv, entry, err)
		}
		nets = append(nets, n)
	}
	return nets, nil
}

// allowlistContains reports whether ip is inside any of the given networks.
func allowlistContains(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
