package core

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/cautils/getter"
	metav1 "github.com/kubescape/kubescape/v3/core/meta/datastructures/v1"
)

const (
	TargetControlsInputs = "controls-inputs"
	TargetExceptions     = "exceptions"
	TargetControl        = "control"
	TargetFramework      = "framework"
	TargetArtifacts      = "artifacts"
	TargetAttackTracks   = "attack-tracks"

	// downloadDirPerm matches the 0700 policy customerloader.go's
	// updateConfigFile() already enforces (and re-tightens with chmod) on
	// ~/.kubescape: setPathAndFilename() defaults downloadInfo.Path to that
	// same directory (getter.GetDefaultPath("")) when no --output path is
	// given, and it holds config.json's AccessKey. A more permissive mode
	// here would race the config loader's own hardening and could leave the
	// directory group-readable depending on which one runs first.
	downloadDirPerm = 0700
)

var downloadFunc = map[string]func(context.Context, *metav1.DownloadInfo) ([]string, error){
	TargetControlsInputs: downloadConfigInputs,
	TargetExceptions:     downloadExceptions,
	TargetControl:        downloadControl,
	TargetFramework:      downloadFramework,
	TargetArtifacts:      downloadArtifacts,
	TargetAttackTracks:   downloadAttackTracks,
}

// Indirection seams used only by the download* functions in this file: by
// default they are the real getter constructors from initutils.go,
// cautils.GetTenantConfig, and getKubernetesApi, which (with no local file,
// no account configured, and/or a reachable cluster) ultimately reach the
// network - GitHub releases, the Kubescape Cloud API, or the Kubernetes API
// server. kubernetesAPIFunc in particular must be stubbed together with
// tenantConfigFunc: it is evaluated eagerly as an argument to
// tenantConfigFunc, so leaving it real still probes the cluster (discovery's
// ServerPreferredResources call) even when tenantConfigFunc itself is faked.
// Tests substitute fakes here to exercise every branch of the download*
// functions without a network or cluster dependency.
//
// policyGetterFunc and exceptionsGetterFunc are also called directly (not
// through these vars) from list.go and scan.go, so swapping them here has no
// effect on those call sites.
var (
	policyGetterFunc       = getPolicyGetter
	exceptionsGetterFunc   = getExceptionsGetter
	attackTracksGetterFunc = getAttackTracksGetter
	configInputsGetterFunc = getConfigInputsGetter
	tenantConfigFunc       = cautils.GetTenantConfig
	kubernetesAPIFunc      = getKubernetesApi
)

func DownloadSupportCommands() []string {
	commands := []string{}
	for key := range downloadFunc {
		commands = append(commands, key)
	}

	// Sort the keys of the map
	sort.Strings(commands)
	return commands
}

func (ks *Kubescape) Download(downloadInfo *metav1.DownloadInfo) (*metav1.DownloadResult, error) {
	setPathAndFilename(downloadInfo)
	if err := os.MkdirAll(downloadInfo.Path, downloadDirPerm); err != nil {
		return nil, err
	}
	files, err := downloadArtifact(ks.Context(), downloadInfo, downloadFunc)
	if err != nil {
		return nil, err
	}
	return &metav1.DownloadResult{Files: files}, nil
}

func downloadArtifact(ctx context.Context, downloadInfo *metav1.DownloadInfo, downloadArtifactFunc map[string]func(context.Context, *metav1.DownloadInfo) ([]string, error)) ([]string, error) {
	if f, ok := downloadArtifactFunc[downloadInfo.Target]; ok {
		files, err := f(ctx, downloadInfo)
		if err != nil {
			return nil, err
		}
		return files, nil
	}
	return nil, fmt.Errorf("unknown command to download")
}

func setPathAndFilename(downloadInfo *metav1.DownloadInfo) {
	// The CLI (cmd/download/download.go) pre-splits a "--output <file>.json"
	// into (dir, file): a bare "nsa.json" arrives here as Path="" +
	// FileName="nsa.json". A FileName set with an empty Path means "current
	// directory", not "no output path given" — defaulting it to ~/.kubescape
	// would silently discard the user's --output file.
	if downloadInfo.FileName != "" {
		if downloadInfo.Path == "" {
			downloadInfo.Path = "."
		}
		return
	}

	if downloadInfo.Path == "" {
		downloadInfo.Path = getter.GetDefaultPath("")
		return
	}

	dir, file := filepath.Split(downloadInfo.Path)
	if dir == "" && file != "." && file != ".." && filepath.Ext(file) != "" {
		// Bare file name (e.g. "nsa.json" passed straight to the API): save
		// it to the current directory instead of misreading it as a directory.
		downloadInfo.FileName = file
		downloadInfo.Path = "."
		return
	}
	if dir == "" {
		// Extension-less bare name: keep treating it as a directory.
		downloadInfo.Path = file
		return
	}
	// Intentionally restricted to ".json" and left as-is: an existing
	// TestSetPathAndFilename case enshrines .txt-in-dir-as-directory behavior.
	if strings.Contains(file, ".json") {
		downloadInfo.Path = filepath.Clean(dir)
		downloadInfo.FileName = file
	}
}

func downloadArtifacts(ctx context.Context, downloadInfo *metav1.DownloadInfo) ([]string, error) {
	downloadInfo.FileName = ""
	var artifacts = map[string]func(context.Context, *metav1.DownloadInfo) ([]string, error){
		TargetControlsInputs: downloadConfigInputs,
		TargetExceptions:     downloadExceptions,
		TargetFramework:      downloadFramework,
		TargetAttackTracks:   downloadAttackTracks,
	}
	var files []string
	var errs []error
	for artifact := range artifacts {
		artifactFiles, err := downloadArtifact(ctx, &metav1.DownloadInfo{
			Target:    artifact,
			Path:      downloadInfo.Path,
			FileName:  fmt.Sprintf("%s.json", artifact),
			AccountID: downloadInfo.AccountID,
			AccessKey: downloadInfo.AccessKey,
		}, artifacts)
		if err != nil {
			logger.L().Ctx(ctx).Warning("error downloading", helpers.String("artifact", artifact), helpers.Error(err))
			errs = append(errs, err)
			continue
		}
		files = append(files, artifactFiles...)
	}
	return files, errors.Join(errs...)
}

func downloadConfigInputs(ctx context.Context, downloadInfo *metav1.DownloadInfo) ([]string, error) {
	tenant := tenantConfigFunc(ctx, downloadInfo.AccountID, downloadInfo.AccessKey, "", "", kubernetesAPIFunc())

	controlsInputsGetter, _, err := configInputsGetterFunc(ctx, downloadInfo.Identifier, tenant.GetAccountID(), nil, false, false)
	if err != nil {
		return nil, err
	}
	controlInputs, err := controlsInputsGetter.GetControlsInputs(ctx, tenant.GetContextName())
	if err != nil {
		return nil, err
	}
	if downloadInfo.FileName == "" {
		downloadInfo.FileName = fmt.Sprintf("%s.json", downloadInfo.Target)
	}
	if controlInputs == nil {
		return nil, fmt.Errorf("failed to download controlInputs - received empty objects")
	}
	// save in file
	downloadTo := filepath.Join(downloadInfo.Path, downloadInfo.FileName)
	err = getter.SaveInFile(controlInputs, downloadTo)
	if err != nil {
		return nil, err
	}
	logger.L().Success("Downloaded", helpers.String("artifact", downloadInfo.Target), helpers.String("path", downloadTo))
	return []string{downloadTo}, nil
}

func downloadExceptions(ctx context.Context, downloadInfo *metav1.DownloadInfo) ([]string, error) {
	tenant := tenantConfigFunc(ctx, downloadInfo.AccountID, downloadInfo.AccessKey, "", "", kubernetesAPIFunc())
	exceptionsGetter, err := exceptionsGetterFunc(ctx, "", tenant.GetAccountID(), nil, false)
	if err != nil {
		return nil, err
	}

	exceptions, err := exceptionsGetter.GetExceptions(ctx, tenant.GetContextName())
	if err != nil {
		return nil, err
	}

	if downloadInfo.FileName == "" {
		downloadInfo.FileName = fmt.Sprintf("%s.json", downloadInfo.Target)
	}
	// save in file
	downloadTo := filepath.Join(downloadInfo.Path, downloadInfo.FileName)
	err = getter.SaveInFile(exceptions, downloadTo)
	if err != nil {
		return nil, err
	}
	logger.L().Ctx(ctx).Success("Downloaded", helpers.String("artifact", downloadInfo.Target), helpers.String("path", downloadTo))
	return []string{downloadTo}, nil
}

func downloadAttackTracks(ctx context.Context, downloadInfo *metav1.DownloadInfo) ([]string, error) {
	var err error
	tenant := tenantConfigFunc(ctx, downloadInfo.AccountID, downloadInfo.AccessKey, "", "", kubernetesAPIFunc())

	attackTracksGetter, err := attackTracksGetterFunc(ctx, "", tenant.GetAccountID(), nil, false)
	if err != nil {
		return nil, err
	}

	attackTracks, err := attackTracksGetter.GetAttackTracks()
	if err != nil {
		return nil, err
	}

	if downloadInfo.FileName == "" {
		downloadInfo.FileName = fmt.Sprintf("%s.json", downloadInfo.Target)
	}
	// save in file
	downloadTo := filepath.Join(downloadInfo.Path, downloadInfo.FileName)
	err = getter.SaveInFile(attackTracks, downloadTo)
	if err != nil {
		return nil, err
	}
	logger.L().Success("Downloaded", helpers.String("attack tracks", downloadInfo.Target), helpers.String("path", downloadTo))
	return []string{downloadTo}, nil

}

func downloadFramework(ctx context.Context, downloadInfo *metav1.DownloadInfo) ([]string, error) {

	tenant := tenantConfigFunc(ctx, downloadInfo.AccountID, downloadInfo.AccessKey, "", "", kubernetesAPIFunc())

	g, err := policyGetterFunc(ctx, nil, tenant.GetAccountID(), true, nil, false)
	if err != nil {
		return nil, err
	}

	if downloadInfo.Identifier == "" {
		// if framework name not specified - download all frameworks
		frameworks, err := g.GetFrameworks()
		if err != nil {
			return nil, err
		}
		var files []string
		for _, fw := range frameworks {
			filename, err := getter.PolicyCacheFilename(fw.Name)
			if err != nil {
				logger.L().Ctx(ctx).Warning("skipping framework with empty name", helpers.Error(err))
				continue
			}
			downloadTo := filepath.Join(downloadInfo.Path, filename)
			err = getter.SaveInFile(fw, downloadTo)
			if err != nil {
				return nil, err
			}
			logger.L().Success("Downloaded", helpers.String("artifact", downloadInfo.Target), helpers.String("name", fw.Name), helpers.String("path", downloadTo))
			files = append(files, downloadTo)
		}
		return files, nil
	}

	if downloadInfo.FileName == "" {
		filename, err := getter.PolicyCacheFilename(downloadInfo.Identifier)
		if err != nil {
			return nil, err
		}
		downloadInfo.FileName = filename
	}
	framework, err := g.GetFramework(downloadInfo.Identifier)
	if err != nil {
		return nil, err
	}
	if framework == nil {
		return nil, fmt.Errorf("failed to download framework - received empty objects")
	}
	downloadTo := filepath.Join(downloadInfo.Path, downloadInfo.FileName)
	err = getter.SaveInFile(framework, downloadTo)
	if err != nil {
		return nil, err
	}
	logger.L().Success("Downloaded", helpers.String("artifact", downloadInfo.Target), helpers.String("name", framework.Name), helpers.String("path", downloadTo))
	return []string{downloadTo}, nil
}

func downloadControl(ctx context.Context, downloadInfo *metav1.DownloadInfo) ([]string, error) {

	tenant := tenantConfigFunc(ctx, downloadInfo.AccountID, downloadInfo.AccessKey, "", "", kubernetesAPIFunc())

	g, err := policyGetterFunc(ctx, nil, tenant.GetAccountID(), false, nil, false)
	if err != nil {
		return nil, err
	}

	if downloadInfo.Identifier == "" {
		// TODO - support
		return nil, fmt.Errorf("missing control ID")
	}
	if downloadInfo.FileName == "" {
		filename, err := getter.PolicyCacheFilename(downloadInfo.Identifier)
		if err != nil {
			return nil, err
		}
		downloadInfo.FileName = filename
	}
	controls, err := g.GetControl(downloadInfo.Identifier)
	if err != nil {
		return nil, fmt.Errorf("failed to download control ID '%s': %w", downloadInfo.Identifier, err)
	}
	if controls == nil {
		return nil, fmt.Errorf("failed to download control id '%s' - received empty objects", downloadInfo.Identifier)
	}
	downloadTo := filepath.Join(downloadInfo.Path, downloadInfo.FileName)
	err = getter.SaveInFile(controls, downloadTo)
	if err != nil {
		return nil, err
	}
	logger.L().Success("Downloaded", helpers.String("artifact", downloadInfo.Target), helpers.String("ID", downloadInfo.Identifier), helpers.String("path", downloadTo))
	return []string{downloadTo}, nil
}
