package imagescan

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

const maxRegistryAPIResponseBytes int64 = 64 << 20

func readRegistryAPIResponse(body io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		limit = maxRegistryAPIResponseBytes
	}

	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read registry api response: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("registry api response exceeds the %d-byte limit", limit)
	}
	return data, nil
}

// FetchImagesInformation provides a shared implementation for GetImagesInformation across adaptors.
func FetchImagesInformation(imageIDs []ContainerImageIdentifier) ([]ContainerImageInformation, error) {
	var infos []ContainerImageInformation
	for _, imageID := range imageIDs {
		infos = append(infos, ContainerImageInformation{
			ImageID: imageID,
			Bom:     []string{},
		})
	}
	return infos, nil
}

// NormalizeSeverity converts common provider severity strings to Kubescape standard.
func NormalizeSeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	case "minimal", "informational", "untriaged", "unassigned", "negligible", "none":
		return "Negligible"
	default:
		return "Unknown"
	}
}

// ProcessImages iterates over imageIDs and calls the provided fetch function, handling errors and aggregating results.
func ProcessImages[T any](
	imageIDs []ContainerImageIdentifier,
	processFunc func(imageID ContainerImageIdentifier) (T, error),
) ([]T, error) {
	var results []T
	var aggErr error

	for _, imageID := range imageIDs {
		res, err := processFunc(imageID)
		if err != nil {
			logger.L().Warning("skipping image due to api error", helpers.Error(err))
			aggErr = errors.Join(aggErr, err)
		}

		results = append(results, res)
	}

	return results, aggErr
}
