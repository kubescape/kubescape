package imagescan

import (
	"errors"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

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
	case "minimal", "informational", "untriaged", "unassigned":
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
