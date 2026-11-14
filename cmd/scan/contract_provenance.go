package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kubescape/kubescape/v4/core/cautils"
	contractv1alpha1 "github.com/kubescape/kubescape/v4/core/pkg/scancontract/v1alpha1"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/spf13/cobra"
)

var validContractSectionsMap = map[string]struct{}{
	"policy":     {},
	"scope":      {},
	"evaluation": {},
	"failure":    {},
	"output":     {},
}

// parseContractAllowlist validates and parses the allowed contract sections.
// Returns nil if no allowlist was provided.
func parseContractAllowlist(rawSections []string) (map[string]bool, error) {
	if len(rawSections) == 0 {
		return nil, nil
	}
	allowed := make(map[string]bool)
	for _, raw := range rawSections {
		for _, part := range strings.Split(raw, ",") {
			token := strings.TrimSpace(part)
			if token == "" {
				return nil, fmt.Errorf("unsupported section \"\" in --contract-allow (supported: policy, scope, evaluation, failure, output)")
			}
			lower := strings.ToLower(token)
			if _, ok := validContractSectionsMap[lower]; !ok {
				return nil, fmt.Errorf("unsupported section %q in --contract-allow (supported: policy, scope, evaluation, failure, output)", part)
			}
			allowed[lower] = true
		}
	}
	return allowed, nil
}

// partitionContractSections divides declared contract sections into allowed and denied sets.
// Both returned slices preserve canonical section ordering.
func partitionContractSections(contract contractv1alpha1.Contract, allowedMap map[string]bool) ([]string, []string) {
	if allowedMap == nil {
		return selectedContractSections(contract), nil
	}
	allowed := make([]string, 0, 5)
	var denied []string

	checkSection := func(name string, exists bool) {
		if !exists {
			return
		}
		if allowedMap[name] {
			allowed = append(allowed, name)
		} else {
			denied = append(denied, name)
		}
	}

	checkSection("policy", contract.Policy != nil)
	checkSection("scope", contract.Scope != nil)
	checkSection("evaluation", contract.Evaluation != nil)
	checkSection("failure", contract.Failure != nil)
	checkSection("output", contract.Output != nil)

	return allowed, denied
}

// filterContractSections returns a copy of the contract with denied sections nilled out.
func filterContractSections(contract contractv1alpha1.Contract, allowedMap map[string]bool) contractv1alpha1.Contract {
	if allowedMap == nil {
		return contract
	}
	filtered := contract
	if !allowedMap["policy"] {
		filtered.Policy = nil
	}
	if !allowedMap["scope"] {
		filtered.Scope = nil
	}
	if !allowedMap["evaluation"] {
		filtered.Evaluation = nil
	}
	if !allowedMap["failure"] {
		filtered.Failure = nil
	}
	if !allowedMap["output"] {
		filtered.Output = nil
	}
	return filtered
}

// newScanContractMetadata captures the resolution that has already happened
// at the CLI boundary. The final policy identifiers and effective-run digest
// are filled in by cautils when the scan session is constructed, because that
// is where the actual policy selection is known for every scan subcommand.
func newScanContractMetadata(
	cmd *cobra.Command,
	selected *contractv1alpha1.SelectedContract,
	path string,
	scanInfo *cautils.ScanInfo,
	gates *reporthandlingv2.ScanContractGateResolution,
	allowedSections []string,
	deniedSections []string,
	effectiveContract contractv1alpha1.Contract,
) *reporthandlingv2.ScanContractMetadata {
	if selected == nil {
		return nil
	}

	metadata := &reporthandlingv2.ScanContractMetadata{
		APIVersion:              selected.APIVersion,
		Name:                    selected.Metadata.Name,
		Contract:                selected.ContractName,
		MinimumKubescapeVersion: selected.MinimumKubescapeVersion,
		DigestSchema:            selected.DigestSchema,
		ContractDigest:          selected.ContractDigest,
		Source:                  safeScanContractSource(path),
		AllowedSections:         allowedSections,
		DeniedSections:          deniedSections,
		Effective:               resolvedContractSettings(cmd, effectiveContract, scanInfo),
		GateResolution:          gates,
		OrdinaryCLIOverrides:    ordinaryCLIOverrides(cmd, effectiveContract, scanInfo),
	}
	return metadata
}

func selectedContractSections(contract contractv1alpha1.Contract) []string {
	sections := make([]string, 0, 5)
	if contract.Policy != nil {
		sections = append(sections, "policy")
	}
	if contract.Scope != nil {
		sections = append(sections, "scope")
	}
	if contract.Evaluation != nil {
		sections = append(sections, "evaluation")
	}
	if contract.Failure != nil {
		sections = append(sections, "failure")
	}
	if contract.Output != nil {
		sections = append(sections, "output")
	}
	return sections
}

func resolvedContractSettings(cmd *cobra.Command, contract contractv1alpha1.Contract, scanInfo *cautils.ScanInfo) *reporthandlingv2.ScanContractEffectiveSettings {
	settings := &reporthandlingv2.ScanContractEffectiveSettings{}

	if contract.Policy != nil {
		settings.Policy = &reporthandlingv2.ScanContractPolicy{
			ControlsVersion: scanInfo.ControlsVersion,
		}
		if contract.Policy.Frameworks != nil {
			settings.Policy.Frameworks = append([]string(nil), (*contract.Policy.Frameworks)...)
		}
		if contract.Policy.Controls != nil {
			settings.Policy.Controls = append([]string(nil), (*contract.Policy.Controls)...)
		}
	}
	if contract.Scope != nil {
		settings.Scope = &reporthandlingv2.ScanContractScope{
			IncludeNamespaces: splitContractNamespaces(scanInfo.IncludeNamespaces),
			ExcludeNamespaces: splitContractNamespaces(scanInfo.ExcludedNamespaces),
		}
	}
	if contract.Evaluation != nil {
		settings.Evaluation = &reporthandlingv2.ScanContractEvaluation{
			ScanTimeout:    scanInfo.ScanTimeout.String(),
			ControlTimeout: scanInfo.ControlTimeout.String(),
		}
	}
	if contract.Failure != nil || commandFlagChanged(cmd, "severity-threshold") || commandFlagChanged(cmd, "compliance-threshold") || commandFlagChanged(cmd, "fail-coverage-below") || commandFlagChanged(cmd, "fail-on-degraded-config") {
		settings.Failure = effectiveFailure(cmd, scanInfo, contract.Failure)
	}
	if contract.Output != nil {
		settings.Output = &reporthandlingv2.ScanContractOutput{
			Formats:          scanInfo.Formats(),
			OmitRawResources: boolPointer(scanInfo.OmitRawResources),
		}
	}

	if settings.Policy == nil && settings.Scope == nil && settings.Evaluation == nil && settings.Failure == nil && settings.Output == nil {
		return nil
	}
	return settings
}

func effectiveFailure(cmd *cobra.Command, scanInfo *cautils.ScanInfo, contract *contractv1alpha1.Failure) *reporthandlingv2.ScanContractFailure {
	failure := &reporthandlingv2.ScanContractFailure{}
	if (contract != nil && contract.SeverityAtLeast != nil) || commandFlagChanged(cmd, "severity-threshold") {
		failure.SeverityAtLeast = stringPointer(scanInfo.FailThresholdSeverity)
	}
	if (contract != nil && contract.ComplianceBelow != nil) || commandFlagChanged(cmd, "compliance-threshold") {
		failure.ComplianceBelow = float64Pointer(float64(scanInfo.ComplianceThreshold))
	}
	if (contract != nil && contract.CoverageBelow != nil) || commandFlagChanged(cmd, "fail-coverage-below") {
		failure.CoverageBelow = float64Pointer(float64(scanInfo.FailCoverageThreshold))
	}
	if (contract != nil && contract.DegradedPolicyInput != nil) || commandFlagChanged(cmd, "fail-on-degraded-config") {
		failure.DegradedPolicyInput = boolPointer(scanInfo.FailOnDegradedConfig)
	}
	return failure
}

func ordinaryCLIOverrides(cmd *cobra.Command, contract contractv1alpha1.Contract, scanInfo *cautils.ScanInfo) *reporthandlingv2.ScanContractCLIOverrides {
	overrides := &reporthandlingv2.ScanContractCLIOverrides{}

	if contract.Policy != nil && contract.Policy.ControlsVersion != nil && commandFlagChanged(cmd, "controls-version") {
		overrides.Policy = &reporthandlingv2.ScanContractPolicyOverrides{ControlsVersion: stringPointer(scanInfo.ControlsVersion)}
	}
	if contract.Scope != nil {
		scope := &reporthandlingv2.ScanContractScopeOverrides{}
		if contract.Scope.IncludeNamespaces != nil && commandFlagChanged(cmd, "include-namespaces") {
			value := splitContractNamespaces(scanInfo.IncludeNamespaces)
			scope.IncludeNamespaces = &value
		}
		if contract.Scope.ExcludeNamespaces != nil && commandFlagChanged(cmd, "exclude-namespaces") {
			value := splitContractNamespaces(scanInfo.ExcludedNamespaces)
			scope.ExcludeNamespaces = &value
		}
		if scope.IncludeNamespaces != nil || scope.ExcludeNamespaces != nil {
			overrides.Scope = scope
		}
	}
	if contract.Evaluation != nil {
		evaluation := &reporthandlingv2.ScanContractEvaluationOverrides{}
		if contract.Evaluation.ScanTimeout != nil && commandFlagChanged(cmd, "scan-timeout") {
			evaluation.ScanTimeout = stringPointer(scanInfo.ScanTimeout.String())
		}
		if contract.Evaluation.ControlTimeout != nil && commandFlagChanged(cmd, "control-timeout") {
			evaluation.ControlTimeout = stringPointer(scanInfo.ControlTimeout.String())
		}
		if evaluation.ScanTimeout != nil || evaluation.ControlTimeout != nil {
			overrides.Evaluation = evaluation
		}
	}
	if contract.Output != nil {
		output := &reporthandlingv2.ScanContractOutputOverrides{}
		if contract.Output.Formats != nil && commandFlagChanged(cmd, "format") {
			value := scanInfo.Formats()
			output.Formats = &value
		}
		if contract.Output.OmitRawResources != nil && commandFlagChanged(cmd, "omit-raw-resources") {
			output.OmitRawResources = boolPointer(scanInfo.OmitRawResources)
		}
		if output.Formats != nil || output.OmitRawResources != nil {
			overrides.Output = output
		}
	}

	if overrides.Policy == nil && overrides.Scope == nil && overrides.Evaluation == nil && overrides.Output == nil {
		return nil
	}
	return overrides
}

func safeScanContractSource(path string) string {
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

func splitContractNamespaces(value string) []string {
	if value == "" {
		return []string{}
	}
	items := make([]string, 0)
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			items = append(items, item)
		}
	}
	return items
}

func stringPointer(value string) *string { return &value }

func float64Pointer(value float64) *float64 { return &value }

func boolPointer(value bool) *bool { return &value }
