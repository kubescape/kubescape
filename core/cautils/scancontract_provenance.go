package cautils

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	contractv1alpha1 "github.com/kubescape/kubescape/v4/core/pkg/scancontract/v1alpha1"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

// effectiveRunDigestInput is intentionally narrower than report metadata. It
// contains only the resolved inputs that determine scan behavior and the
// authorization decision. The contract path and report-only provenance are not
// part of this digest.
type effectiveRunDigestInput struct {
	DigestSchema     string                                          `json:"digestSchema"`
	KubescapeVersion string                                          `json:"kubescapeVersion"`
	Effective        *reporthandlingv2.ScanContractEffectiveSettings `json:"effective"`
	AllowedSections  []string                                        `json:"allowedSections"`
	DeniedSections   []string                                        `json:"deniedSections"`
	RunnerInputs     []reporthandlingv2.ScanContractRunnerInput      `json:"runnerInputs"`
}

// finalizeScanContractMetadata runs at the point where Kubescape knows the
// actual policy identifiers handed to the scanner. This makes report metadata
// describe the executed selection even for scan subcommands that replace a
// contract's policy selection.
func finalizeScanContractMetadata(scanInfo *ScanInfo, policyIdentifiers []PolicyIdentifier) *reporthandlingv2.ScanContractMetadata {
	if scanInfo.ScanContract == nil {
		return nil
	}

	metadata := *scanInfo.ScanContract
	metadata.AllowedSections = append([]string(nil), scanInfo.ScanContract.AllowedSections...)
	metadata.DeniedSections = append([]string(nil), scanInfo.ScanContract.DeniedSections...)
	metadata.RunnerInputs = append([]reporthandlingv2.ScanContractRunnerInput(nil), scanInfo.ScanContract.RunnerInputs...)
	metadata.Effective = cloneEffectiveSettings(scanInfo.ScanContract.Effective)

	if metadata.Effective != nil && metadata.Effective.Policy != nil && len(policyIdentifiers) > 0 {
		policy := *metadata.Effective.Policy
		policy.Frameworks = nil
		policy.Controls = nil
		for _, identifier := range policyIdentifiers {
			switch identifier.Kind {
			case apisv1.KindFramework:
				policy.Frameworks = append(policy.Frameworks, identifier.Identifier)
			case apisv1.KindControl:
				policy.Controls = append(policy.Controls, identifier.Identifier)
			}
		}
		metadata.Effective.Policy = &policy
	}

	digest, err := contractv1alpha1.DigestEffectiveRun(effectiveRunDigestInput{
		DigestSchema:     contractv1alpha1.EffectiveRunDigestSchema,
		KubescapeVersion: versioncheck.BuildNumber,
		Effective:        metadata.Effective,
		AllowedSections:  metadata.AllowedSections,
		DeniedSections:   metadata.DeniedSections,
		RunnerInputs:     metadata.RunnerInputs,
	})
	if err != nil {
		logger.L().Warning("failed to derive repository scan contract effective-run digest", helpers.Error(err))
	} else {
		metadata.EffectiveRunDigest = digest
	}

	return &metadata
}

func cloneEffectiveSettings(settings *reporthandlingv2.ScanContractEffectiveSettings) *reporthandlingv2.ScanContractEffectiveSettings {
	if settings == nil {
		return nil
	}
	clone := *settings
	if settings.Policy != nil {
		policy := *settings.Policy
		policy.Frameworks = append([]string(nil), settings.Policy.Frameworks...)
		policy.Controls = append([]string(nil), settings.Policy.Controls...)
		clone.Policy = &policy
	}
	if settings.Scope != nil {
		scope := *settings.Scope
		scope.IncludeNamespaces = append([]string(nil), settings.Scope.IncludeNamespaces...)
		scope.ExcludeNamespaces = append([]string(nil), settings.Scope.ExcludeNamespaces...)
		clone.Scope = &scope
	}
	if settings.Output != nil {
		output := *settings.Output
		output.Formats = append([]string(nil), settings.Output.Formats...)
		clone.Output = &output
	}
	return &clone
}

// RecordScanContractRunnerInputs records only the local runner files whose
// exact bytes were successfully consumed by the policy getters. It never
// rereads a path for hashing, avoiding a hash-then-load race.
func RecordScanContractRunnerInputs(scanInfo *ScanInfo, getters *Getters) {
	if scanInfo == nil || scanInfo.ScanContract == nil || getters == nil {
		return
	}

	inputs := make([]reporthandlingv2.ScanContractRunnerInput, 0, 2)
	if input, ok := consumedRunnerInput("controlsConfig", getters.ControlsInputsGetter); ok {
		inputs = append(inputs, input)
	}
	if input, ok := consumedRunnerInput("exceptions", getters.ExceptionsGetter); ok {
		inputs = append(inputs, input)
	}
	scanInfo.ScanContract.RunnerInputs = inputs
}

func consumedRunnerInput(role string, source any) (reporthandlingv2.ScanContractRunnerInput, bool) {
	digester, ok := source.(getter.ConsumedFileDigester)
	if !ok {
		return reporthandlingv2.ScanContractRunnerInput{}, false
	}
	path, digest, ok := digester.ConsumedFileDigest()
	if !ok {
		return reporthandlingv2.ScanContractRunnerInput{}, false
	}
	return reporthandlingv2.ScanContractRunnerInput{
		Role:   role,
		Source: safeContractRunnerInputSource(path),
		Digest: digest,
	}, true
}

func safeContractRunnerInputSource(path string) string {
	clean := filepath.Clean(path)
	if filepath.IsAbs(clean) {
		if workingDirectory, err := os.Getwd(); err == nil {
			if relative, err := filepath.Rel(workingDirectory, clean); err == nil {
				clean = relative
			}
		}
	}
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || filepath.IsAbs(clean) {
		return "external"
	}
	return filepath.ToSlash(clean)
}
