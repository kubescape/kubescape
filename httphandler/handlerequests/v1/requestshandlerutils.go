package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

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
			//TODO(ttimonen) should we actually pass the PostureReport here somehow?
			response.Type = utilsapisv1.ResultsV1ScanResponseType
		}
	}

	handler.state.setNotBusy(scanReq.scanID)

	// return results, if someone's waiting for them; never block.
	select {
	case scanReq.resp <- response:
	default:
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
		return nil, err
	}

	if !skipPersistence {
		store := storage.GetStorage()
		// do not store results locally when we are sending them
		if store != nil && config.GetAccount() == "" {
			pr := result.GetResults()

			if err := store.StorePostureReportResults(ctx, pr); err != nil {
				return nil, err
			}
		} else {
			logger.L().Debug("storage is not initialized - skipping storing results")
		}
	} else {
		logger.L().Info("skipPersistence=true, skipping storing results")
	}

	return nil, nil
}

func readResultsFile(fileID string) (*reporthandlingv2.PostureReport, error) {
	parsedUUID, err := uuid.Parse(fileID)
	if err != nil {
		logger.L().Warning("invalid scan ID requested", helpers.String("ID", fileID), helpers.Error(err))
		return nil, fmt.Errorf("invalid scan ID format")
	}
	cleanID := parsedUUID.String()

	dirs := []string{OutputDir, FailedOutputDir}
	extensions := []string{"", ".json"}

	for _, dir := range dirs {
		for _, ext := range extensions {
			path := filepath.Join(dir, cleanID+ext)
			f, err := os.ReadFile(path)
			if err == nil {
				postureReport := &reporthandlingv2.PostureReport{}
				err = json.Unmarshal(f, postureReport)
				return postureReport, err
			}
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
