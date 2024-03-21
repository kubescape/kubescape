package v1

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	utilsmetav1 "github.com/kubescape/opa-utils/httpserver/meta/v1"
	"k8s.io/utils/strings/slices"

	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"
)

func ToScanInfo(scanRequest *utilsmetav1.PostScanRequest) *cautils.ScanInfo {
	scanInfo := defaultScanInfo()

	setTargetInScanInfo(scanRequest, scanInfo)

	if scanRequest.Account != "" {
		scanInfo.AccountID = scanRequest.Account
	}
	if scanRequest.AccessKey != "" {
		scanInfo.AccessKey = scanRequest.AccessKey
	}
	if len(scanRequest.ExcludedNamespaces) > 0 {
		scanInfo.ExcludedNamespaces = strings.Join(scanRequest.ExcludedNamespaces, ",")
	}
	if len(scanRequest.IncludeNamespaces) > 0 {
		scanInfo.IncludeNamespaces = strings.Join(scanRequest.IncludeNamespaces, ",")
	}

	if scanRequest.Format != "" {
		scanInfo.Format = scanRequest.Format
	}

	// UseCachedArtifacts
	if scanRequest.UseCachedArtifacts != nil {
		if useCachedArtifacts := cautils.NewBoolPtr(scanRequest.UseCachedArtifacts); useCachedArtifacts.Get() != nil && *useCachedArtifacts.Get() {
			scanInfo.UseArtifactsFrom = getter.DefaultLocalStore // Load files from cache (this will prevent kubescape fom downloading the artifacts every time)
		}
	}

	// KeepLocal
	if scanRequest.KeepLocal != nil {
		if keepLocal := cautils.NewBoolPtr(scanRequest.KeepLocal); keepLocal.Get() != nil {
			scanInfo.Local = *keepLocal.Get() // Load files from cache (this will prevent kubescape fom downloading the artifacts every time)
		}
	}

	// submit
	if scanRequest.Submit != nil {
		if submit := cautils.NewBoolPtr(scanRequest.Submit); submit.Get() != nil {
			scanInfo.Submit = *submit.Get()
		}
	}

	// host scanner
	if scanRequest.HostScanner != nil {
		scanInfo.HostSensorEnabled = cautils.NewBoolPtr(scanRequest.HostScanner)
	}

	// single resource scan
	if scanRequest.ScanObject != nil {
		scanInfo.ScanObject = scanRequest.ScanObject
	}

	if scanRequest.IsDeletedScanObject != nil {
		scanInfo.IsDeletedScanObject = *scanRequest.IsDeletedScanObject
	}

	if scanRequest.Exceptions != nil {
		scanInfo.UseExceptions = loadexception(scanRequest)

	}
	return scanInfo
}

func setTargetInScanInfo(scanRequest *utilsmetav1.PostScanRequest, scanInfo *cautils.ScanInfo) {
	if scanRequest.TargetType != "" && len(scanRequest.TargetNames) > 0 {
		if strings.EqualFold(string(scanRequest.TargetType), string(apisv1.KindFramework)) {
			scanRequest.TargetType = apisv1.KindFramework
			scanInfo.FrameworkScan = true
			scanInfo.ScanAll = slices.Contains(scanRequest.TargetNames, "all") || slices.Contains(scanRequest.TargetNames, "")
			scanRequest.TargetNames = slices.Filter(nil, scanRequest.TargetNames, func(e string) bool { return e != "" && e != "all" })
		} else if strings.EqualFold(string(scanRequest.TargetType), string(apisv1.KindControl)) {
			scanRequest.TargetType = apisv1.KindControl
			scanInfo.ScanAll = false
		} else {
			// unknown policy kind - set scan all
			scanInfo.FrameworkScan = true
			scanInfo.ScanAll = true
			scanRequest.TargetNames = []string{}
		}
		scanInfo.SetPolicyIdentifiers(scanRequest.TargetNames, scanRequest.TargetType)
	} else {
		scanInfo.FrameworkScan = true
		scanInfo.ScanAll = true
	}
}

func loadexception(exceptions *utilsmetav1.PostScanRequest) (path string) {
	exceptionJSON, err := json.Marshal(exceptions.Exceptions)
	if err != nil {
		logger.L().Error("Failed to marshal exceptions", helpers.Error(err))
	} else {
		exePath, err := os.Executable()
		if err != nil {
			fmt.Printf("Failed to get executable path, reason: %s", err)
		}
		exeDir := filepath.Dir(exePath)
		exdir := filepath.Dir(exeDir)
		edir := filepath.Dir(exdir)
		exceptionpath := filepath.Join(edir, ".kubescape", "exceptions.json")
		if err := os.WriteFile(exceptionpath, exceptionJSON, 0644); err != nil {
			logger.L().Error("Failed to write exceptions file to disk", helpers.String("path", exceptionpath), helpers.Error(err))
			return
		}
		print(exceptionpath)
		return exceptionpath // to test
	}
	return
}
