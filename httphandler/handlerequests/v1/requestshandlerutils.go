package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/armosec/utils-go/boolutils"
	"github.com/kubescape/backend/pkg/versioncheck"
	logger "github.com/kubescape/go-logger"
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

func (handler *HTTPHandler) executeScan(scanReq *scanRequestParams) {
	response := &utilsmetav1.Response{}

	logger.L().Info("scan triggered", helpers.String("ID", scanReq.scanID))
	_, err := scan(scanReq.ctx, scanReq.scanInfo, scanReq.scanID)
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

	// return results
	handler.scanResponseChan.push(scanReq.scanID, response)
}

// executeScan execute the scan request passed in the channel
func (handler *HTTPHandler) watchForScan() {
	for {
		scanReq := <-handler.scanRequestChan
		logger.L().Info("triggering scan", helpers.String("scanID", scanReq.scanID))
		handler.executeScan(scanReq)
	}
}
func scan(ctx context.Context, scanInfo *cautils.ScanInfo, scanID string) (*reporthandlingv2.PostureReport, error) {
	ctx, spanScan := otel.Tracer("").Start(ctx, "kubescape.scan")
	defer spanScan.End()

	ks := core.NewKubescape()

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

	result, err := ks.Scan(ctx, scanInfo)
	if err != nil {
		return nil, writeScanErrorToFile(err, scanID)
	}
	if err := result.HandleResults(ctx); err != nil {
		return nil, err
	}
	storage := storage.GetStorage()
	if storage != nil {
		pr := result.GetResults()

		if err := storage.StorePostureReportResults(ctx, pr); err != nil {
			return nil, err
		}
	} else {
		logger.L().Debug("storage is not initialized - skipping storing results")
	}

	return nil, nil
}

func readResultsFile(fileID string) (*reporthandlingv2.PostureReport, error) {
	if fileName := searchFile(fileID); fileName != "" {
		f, err := os.ReadFile(fileName)
		if err != nil {
			return nil, err
		}
		postureReport := &reporthandlingv2.PostureReport{}
		err = json.Unmarshal(f, postureReport)
		return postureReport, err
	}
	return nil, fmt.Errorf("file %s not found", fileID)
}

func removeResultDirs() {
	os.ReadDir(OutputDir)
	os.ReadDir(FailedOutputDir)
}
func removeResultsFile(fileID string) error {
	if fileName := searchFile(fileID); fileName != "" {
		return os.Remove(fileName)
	}
	return nil // no files found to delete
}
func searchFile(fileID string) string {
	if fileName, _ := findFile(OutputDir, fileID); fileName != "" {
		return fileName
	}
	if fileName, _ := findFile(FailedOutputDir, fileID); fileName != "" {
		return fileName
	}
	return ""
}

func findFile(targetDir string, fileName string) (string, error) {
	var files []string
	err := filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		files = append(files, path)
		return nil
	})
	if err != nil {
		return "", err
	}
	for i := range files {
		if strings.Contains(files[i], fileName) {
			return files[i], nil
		}
	}
	return "", nil
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
	scanInfo.AccountID = envToString("KS_ACCOUNT_ID", config.GetAccount())         // publish results to Kubescape SaaS
	scanInfo.AccessKey = envToString("KS_ACCESS_KEY", config.GetAccessKey())       // publish results to Kubescape SaaS
	scanInfo.ExcludedNamespaces = envToString("KS_EXCLUDE_NAMESPACES", "")         // namespaces to exclude
	scanInfo.IncludeNamespaces = envToString("KS_INCLUDE_NAMESPACES", "")          // namespaces to include
	scanInfo.HostSensorYamlPath = envToString("KS_HOST_SCAN_YAML", "")             // path to host scan YAML
	scanInfo.FormatVersion = envToString("KS_FORMAT_VERSION", "v2")                // output format version
	scanInfo.Format = envToString("KS_FORMAT", "json")                             // default output should be json
	scanInfo.Submit = envToBool("KS_SUBMIT", false)                                // publish results to Kubescape SaaS
	scanInfo.Local = envToBool("KS_KEEP_LOCAL", false)                             // do not publish results to Kubescape SaaS
	scanInfo.HostSensorEnabled.SetBool(envToBool("KS_ENABLE_HOST_SCANNER", false)) // enable host scanner
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

func writeScanErrorToFile(err error, scanID string) error {
	if e := os.MkdirAll(filepath.Dir(FailedOutputDir), os.ModePerm); e != nil {
		return fmt.Errorf("failed to scan. reason: '%s'. failed to save error in file - failed to create directory. reason: %s", err.Error(), e.Error())
	}
	f, e := os.Create(filepath.Join(filepath.Dir(FailedOutputDir), scanID))
	if e != nil {
		return fmt.Errorf("failed to scan. reason: '%s'. failed to save error in file - failed to open file for writing. reason: %s", err.Error(), e.Error())
	}
	defer f.Close()

	if _, e := f.Write([]byte(err.Error())); e != nil {
		return fmt.Errorf("failed to scan. reason: '%s'. failed to save error in file - failed to write. reason: %s", err.Error(), e.Error())
	}
	return fmt.Errorf("failed to scan. reason: '%s'", err.Error())
}

// responseToBytes convert response object to bytes
func responseToBytes(res *utilsmetav1.Response) []byte {
	b, _ := json.Marshal(res)
	return b
}
