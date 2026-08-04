package core

import (
	"context"
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

var downloadFunc = map[string]func(context.Context, *metav1.DownloadInfo) error{
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

func (ks *Kubescape) Download(downloadInfo *metav1.DownloadInfo) error {
	setPathAndFilename(downloadInfo)
	if err := os.MkdirAll(downloadInfo.Path, downloadDirPerm); err != nil {
		return err
	}
	if err := downloadArtifact(ks.Context(), downloadInfo, downloadFunc); err != nil {
		return err
	}
	return nil
}

func downloadArtifact(ctx context.Context, downloadInfo *metav1.DownloadInfo, downloadArtifactFunc map[string]func(context.Context, *metav1.DownloadInfo) error) error {
	if f, ok := downloadArtifactFunc[downloadInfo.Target]; ok {
		if err := f(ctx, downloadInfo); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("unknown command to download")
}

func setPathAndFilename(downloadInfo *metav1.DownloadInfo) {
	if downloadInfo.Path == "" {
		downloadInfo.Path = getter.GetDefaultPath("")
		return
	}
	dir, file := filepath.Split(downloadInfo.Path)
	if dir == "" {
		downloadInfo.Path = file
		return
	}
	if strings.Contains(file, ".json") {
		downloadInfo.Path = filepath.Clean(dir)
		downloadInfo.FileName = file
	}
}

func downloadArtifacts(ctx context.Context, downloadInfo *metav1.DownloadInfo) error {
	downloadInfo.FileName = ""
	var artifacts = map[string]func(context.Context, *metav1.DownloadInfo) error{
		"controls-inputs": downloadConfigInputs,
		"exceptions":      downloadExceptions,
		"framework":       downloadFramework,
		"attack-tracks":   downloadAttackTracks,
	}
	for artifact := range artifacts {
		if err := downloadArtifact(ctx, &metav1.DownloadInfo{Target: artifact, Path: downloadInfo.Path, FileName: fmt.Sprintf("%s.json", artifact)}, artifacts); err != nil {
			logger.L().Ctx(ctx).Warning("error downloading", helpers.String("artifact", artifact), helpers.Error(err))
		}
	}
	return nil
}

func downloadConfigInputs(ctx context.Context, downloadInfo *metav1.DownloadInfo) error {
	tenant := tenantConfigFunc(ctx, downloadInfo.AccountID, downloadInfo.AccessKey, "", "", kubernetesAPIFunc())

	controlsInputsGetter, _, err := configInputsGetterFunc(ctx, downloadInfo.Identifier, tenant.GetAccountID(), nil, false, false)
	if err != nil {
		return err
	}
	controlInputs, err := controlsInputsGetter.GetControlsInputs(tenant.GetContextName())
	if err != nil {
		return err
	}
	if downloadInfo.FileName == "" {
		downloadInfo.FileName = fmt.Sprintf("%s.json", downloadInfo.Target)
	}
	if controlInputs == nil {
		return fmt.Errorf("failed to download controlInputs - received empty objects")
	}
	// save in file
	err = getter.SaveInFile(controlInputs, filepath.Join(downloadInfo.Path, downloadInfo.FileName))
	if err != nil {
		return err
	}
	logger.L().Success("Downloaded", helpers.String("artifact", downloadInfo.Target), helpers.String("path", filepath.Join(downloadInfo.Path, downloadInfo.FileName)))
	return nil
}

func downloadExceptions(ctx context.Context, downloadInfo *metav1.DownloadInfo) error {
	tenant := tenantConfigFunc(ctx, downloadInfo.AccountID, downloadInfo.AccessKey, "", "", kubernetesAPIFunc())
	exceptionsGetter, err := exceptionsGetterFunc(ctx, "", tenant.GetAccountID(), nil, false)
	if err != nil {
		return err
	}

	exceptions, err := exceptionsGetter.GetExceptions(tenant.GetContextName())
	if err != nil {
		return err
	}

	if downloadInfo.FileName == "" {
		downloadInfo.FileName = fmt.Sprintf("%s.json", downloadInfo.Target)
	}
	// save in file
	err = getter.SaveInFile(exceptions, filepath.Join(downloadInfo.Path, downloadInfo.FileName))
	if err != nil {
		return err
	}
	logger.L().Ctx(ctx).Success("Downloaded", helpers.String("artifact", downloadInfo.Target), helpers.String("path", filepath.Join(downloadInfo.Path, downloadInfo.FileName)))
	return nil
}

func downloadAttackTracks(ctx context.Context, downloadInfo *metav1.DownloadInfo) error {
	var err error
	tenant := tenantConfigFunc(ctx, downloadInfo.AccountID, downloadInfo.AccessKey, "", "", kubernetesAPIFunc())

	attackTracksGetter, err := attackTracksGetterFunc(ctx, "", tenant.GetAccountID(), nil, false)
	if err != nil {
		return err
	}

	attackTracks, err := attackTracksGetter.GetAttackTracks()
	if err != nil {
		return err
	}

	if downloadInfo.FileName == "" {
		downloadInfo.FileName = fmt.Sprintf("%s.json", downloadInfo.Target)
	}
	// save in file
	err = getter.SaveInFile(attackTracks, filepath.Join(downloadInfo.Path, downloadInfo.FileName))
	if err != nil {
		return err
	}
	logger.L().Success("Downloaded", helpers.String("attack tracks", downloadInfo.Target), helpers.String("path", filepath.Join(downloadInfo.Path, downloadInfo.FileName)))
	return nil

}

func downloadFramework(ctx context.Context, downloadInfo *metav1.DownloadInfo) error {

	tenant := tenantConfigFunc(ctx, downloadInfo.AccountID, downloadInfo.AccessKey, "", "", kubernetesAPIFunc())

	g, err := policyGetterFunc(ctx, nil, tenant.GetAccountID(), true, nil, false)
	if err != nil {
		return err
	}

	if downloadInfo.Identifier == "" {
		// if framework name not specified - download all frameworks
		frameworks, err := g.GetFrameworks()
		if err != nil {
			return err
		}
		for _, fw := range frameworks {
			filename, err := getter.PolicyCacheFilename(fw.Name)
			if err != nil {
				logger.L().Ctx(ctx).Warning("skipping framework with empty name", helpers.Error(err))
				continue
			}
			downloadTo := filepath.Join(downloadInfo.Path, filename)
			err = getter.SaveInFile(fw, downloadTo)
			if err != nil {
				return err
			}
			logger.L().Success("Downloaded", helpers.String("artifact", downloadInfo.Target), helpers.String("name", fw.Name), helpers.String("path", downloadTo))
		}
		// return fmt.Errorf("missing framework name")
	} else {
		if downloadInfo.FileName == "" {
			filename, err := getter.PolicyCacheFilename(downloadInfo.Identifier)
			if err != nil {
				return err
			}
			downloadInfo.FileName = filename
		}
		framework, err := g.GetFramework(downloadInfo.Identifier)
		if err != nil {
			return err
		}
		if framework == nil {
			return fmt.Errorf("failed to download framework - received empty objects")
		}
		downloadTo := filepath.Join(downloadInfo.Path, downloadInfo.FileName)
		err = getter.SaveInFile(framework, downloadTo)
		if err != nil {
			return err
		}
		logger.L().Success("Downloaded", helpers.String("artifact", downloadInfo.Target), helpers.String("name", framework.Name), helpers.String("path", downloadTo))
	}
	return nil
}

func downloadControl(ctx context.Context, downloadInfo *metav1.DownloadInfo) error {

	tenant := tenantConfigFunc(ctx, downloadInfo.AccountID, downloadInfo.AccessKey, "", "", kubernetesAPIFunc())

	g, err := policyGetterFunc(ctx, nil, tenant.GetAccountID(), false, nil, false)
	if err != nil {
		return err
	}

	if downloadInfo.Identifier == "" {
		// TODO - support
		return fmt.Errorf("missing control ID")
	}
	if downloadInfo.FileName == "" {
		filename, err := getter.PolicyCacheFilename(downloadInfo.Identifier)
		if err != nil {
			return err
		}
		downloadInfo.FileName = filename
	}
	controls, err := g.GetControl(downloadInfo.Identifier)
	if err != nil {
		return fmt.Errorf("failed to download control ID '%s': %w", downloadInfo.Identifier, err)
	}
	if controls == nil {
		return fmt.Errorf("failed to download control id '%s' - received empty objects", downloadInfo.Identifier)
	}
	downloadTo := filepath.Join(downloadInfo.Path, downloadInfo.FileName)
	err = getter.SaveInFile(controls, downloadTo)
	if err != nil {
		return err
	}
	logger.L().Success("Downloaded", helpers.String("artifact", downloadInfo.Target), helpers.String("ID", downloadInfo.Identifier), helpers.String("path", downloadTo))
	return nil
}
