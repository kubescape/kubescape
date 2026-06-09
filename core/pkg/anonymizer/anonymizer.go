package anonymizer

import "github.com/kubescape/kubescape/v3/core/pkg/resultshandling"

func Apply(resultsHandler *resultshandling.ResultsHandler) error {
	if resultsHandler == nil || resultsHandler.ScanData == nil {
		return nil
	}

	mapping := NewMapping()

	if err := anonymizeSession(resultsHandler.ScanData, mapping); err != nil {
		return err
	}

	return nil
}
