package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/core"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
)

type Downloader interface {
	Download(downloadInfo *metav1.DownloadInfo) (*metav1.DownloadResult, error)
}

var backoffFactory = func() backoff.BackOff {
	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = 3 * time.Minute
	return b
}

func downloadArtifacts(ks Downloader, downloads []metav1.DownloadInfo) error {
	var errs []error
	for _, download := range downloads {
		var result *metav1.DownloadResult
		var err error

		d := download // copy for closure

		operation := func() error {
			result, err = ks.Download(&d)
			if err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
					errors.Is(err, os.ErrPermission) || errors.Is(err, os.ErrNotExist) {
					return backoff.Permanent(err)
				}
				return err
			}
			return nil
		}

		b := backoffFactory()

		if retryErr := backoff.Retry(operation, b); retryErr != nil {
			logger.L().Error("failed to download artifact", helpers.Error(retryErr), helpers.String("target", d.Target))
			errs = append(errs, retryErr)
			continue
		}

		logger.L().Success("downloaded artifacts", helpers.String("count", fmt.Sprintf("%d", len(result.Files))), helpers.String("files", strings.Join(result.Files, ", ")))
	}
	return errors.Join(errs...)
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	ks := core.NewKubescape(ctx)
	downloads := []metav1.DownloadInfo{
		{Target: "artifacts"},                         // download all artifacts
		{Target: "framework", Identifier: "security"}, // force add the "security" framework
	}
	if err := downloadArtifacts(ks, downloads); err != nil {
		logger.L().Error("failed to download all artifacts", helpers.Error(err))
		os.Exit(1)
	}
}
