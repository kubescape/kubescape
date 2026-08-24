package scan

import (
	"fmt"
	"strings"

	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/cmd/shared"
	"github.com/kubescape/kubescape/v4/core/cautils"
	contractv1alpha1 "github.com/kubescape/kubescape/v4/core/pkg/scancontract/v1alpha1"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	reporthandlingapis "github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/spf13/cobra"
)

// loadAndApplyScanContract is the single boundary between the repository-owned
// contract and the existing CLI scan model. Contract values are applied first,
// while flags Cobra marked as changed retain ordinary CLI precedence. Failure
// gates are different: an explicit runner value is a floor that the contract
// may tighten, but never weaken.
func loadAndApplyScanContract(cmd *cobra.Command, scanInfo *cautils.ScanInfo, path, name string) (*contractv1alpha1.SelectedContract, error) {
	if path == "" {
		if name != "" {
			return nil, fmt.Errorf("--contract requires --scan-contract")
		}
		return nil, nil
	}

	selected, err := contractv1alpha1.LoadFile(path, contractv1alpha1.LoadOptions{
		ContractName:        name,
		RunningVersion:      versioncheck.BuildNumber,
		SupportedFormats:    shared.ScanFormats,
		SupportedSeverities: reporthandlingapis.GetSupportedSeverities(),
	})
	if err != nil {
		return nil, err
	}
	if err := validateContractRunnerConflicts(selected, scanInfo); err != nil {
		return nil, err
	}

	applyContractOrdinarySettings(cmd, scanInfo, selected.Contract)
	applyContractGateFloors(cmd, scanInfo, selected.Contract)
	return selected, nil
}

func validateContractRunnerConflicts(selected *contractv1alpha1.SelectedContract, scanInfo *cautils.ScanInfo) error {
	if selected == nil || selected.Contract.Policy == nil || selected.Contract.Policy.ControlsVersion == nil {
		return nil
	}

	var conflicts []string
	if scanInfo.AccountID != "" {
		conflicts = append(conflicts, "--account")
	}
	if scanInfo.UseArtifactsFrom != "" {
		conflicts = append(conflicts, "--use-artifacts-from")
	}
	if len(scanInfo.UseFrom) > 0 {
		conflicts = append(conflicts, "--use-from")
	}
	if scanInfo.UseDefault {
		conflicts = append(conflicts, "--use-default")
	}
	if len(conflicts) > 0 {
		return fmt.Errorf("scan contract policy.controlsVersion cannot be used with %s because that mode bypasses the versioned policy download", strings.Join(conflicts, ", "))
	}
	return nil
}

func applyContractOrdinarySettings(cmd *cobra.Command, scanInfo *cautils.ScanInfo, contract contractv1alpha1.Contract) {
	if contract.Policy != nil && contract.Policy.ControlsVersion != nil && !commandFlagChanged(cmd, "controls-version") {
		scanInfo.ControlsVersion = *contract.Policy.ControlsVersion
	}
	if contract.Scope != nil {
		includeChanged := commandFlagChanged(cmd, "include-namespaces")
		excludeChanged := commandFlagChanged(cmd, "exclude-namespaces")
		if contract.Scope.IncludeNamespaces != nil && !includeChanged && !excludeChanged {
			scanInfo.IncludeNamespaces = strings.Join(*contract.Scope.IncludeNamespaces, ",")
		}
		if contract.Scope.ExcludeNamespaces != nil && !includeChanged && !excludeChanged {
			scanInfo.ExcludedNamespaces = strings.Join(*contract.Scope.ExcludeNamespaces, ",")
		}
	}
	if contract.Evaluation != nil {
		if contract.Evaluation.ScanTimeout != nil && !commandFlagChanged(cmd, "scan-timeout") {
			scanInfo.ScanTimeout = contract.Evaluation.ScanTimeout.Duration
		}
		if contract.Evaluation.ControlTimeout != nil && !commandFlagChanged(cmd, "control-timeout") {
			scanInfo.ControlTimeout = contract.Evaluation.ControlTimeout.Duration
		}
	}
	if contract.Output != nil {
		if contract.Output.Formats != nil && !commandFlagChanged(cmd, "format") {
			scanInfo.Format = strings.Join(*contract.Output.Formats, ",")
		}
		if contract.Output.OmitRawResources != nil && !commandFlagChanged(cmd, "omit-raw-resources") {
			scanInfo.OmitRawResources = *contract.Output.OmitRawResources
		}
	}
}

func applyContractGateFloors(cmd *cobra.Command, scanInfo *cautils.ScanInfo, contract contractv1alpha1.Contract) {
	if contract.Failure == nil {
		return
	}

	if contract.Failure.SeverityAtLeast != nil {
		contractValue := *contract.Failure.SeverityAtLeast
		if commandFlagChanged(cmd, "severity-threshold") {
			effective, floorWon := stricterSeverity(contractValue, scanInfo.FailThresholdSeverity)
			scanInfo.FailThresholdSeverity = effective
			logIgnoredWeakerGate("severityAtLeast", floorWon)
		} else {
			scanInfo.FailThresholdSeverity = contractValue
		}
	}
	if contract.Failure.ComplianceBelow != nil {
		contractValue := float32(*contract.Failure.ComplianceBelow)
		floorWon := commandFlagChanged(cmd, "compliance-threshold") && scanInfo.ComplianceThreshold > contractValue
		if contractValue > scanInfo.ComplianceThreshold {
			scanInfo.ComplianceThreshold = contractValue
		}
		logIgnoredWeakerGate("complianceBelow", floorWon)
	}
	if contract.Failure.CoverageBelow != nil {
		contractValue := float32(*contract.Failure.CoverageBelow)
		floorWon := commandFlagChanged(cmd, "fail-coverage-below") && scanInfo.FailCoverageThreshold > contractValue
		if contractValue > scanInfo.FailCoverageThreshold {
			scanInfo.FailCoverageThreshold = contractValue
		}
		logIgnoredWeakerGate("coverageBelow", floorWon)
	}
	if contract.Failure.DegradedPolicyInput != nil {
		contractFails := *contract.Failure.DegradedPolicyInput == contractv1alpha1.DegradedPolicyInputFail
		floorWon := commandFlagChanged(cmd, "fail-on-degraded-config") && scanInfo.FailOnDegradedConfig && !contractFails
		scanInfo.FailOnDegradedConfig = scanInfo.FailOnDegradedConfig || contractFails
		logIgnoredWeakerGate("degradedPolicyInput", floorWon)
	}
}

func commandFlagChanged(cmd *cobra.Command, name string) bool {
	if flag := cmd.Flags().Lookup(name); flag != nil {
		return flag.Changed
	}
	if flag := cmd.InheritedFlags().Lookup(name); flag != nil {
		return flag.Changed
	}
	return false
}

func stricterSeverity(contractValue, runnerFloor string) (string, bool) {
	if runnerFloor == "" {
		return contractValue, false
	}
	if severityStrictness(runnerFloor) <= severityStrictness(contractValue) {
		return runnerFloor, !strings.EqualFold(strings.TrimSpace(runnerFloor), strings.TrimSpace(contractValue))
	}
	return contractValue, false
}

// Lower severity boundaries are stricter because they fail on a wider set of
// findings. Unknown is kept last for compatibility with the existing accepted
// severity vocabulary; validation still owns whether it is executable.
func severityStrictness(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "low":
		return 0
	case "medium":
		return 1
	case "high":
		return 2
	case "critical":
		return 3
	default:
		return 4
	}
}

func logIgnoredWeakerGate(field string, ignored bool) {
	if ignored {
		logger.L().Info("Scan contract gate cannot weaken the explicit CLI floor", helpers.String("field", field))
	}
}

func contractPolicyIdentifiers(selected *contractv1alpha1.SelectedContract) []cautils.PolicyIdentifier {
	if selected == nil || selected.Contract.Policy == nil {
		return nil
	}
	policy := selected.Contract.Policy
	var identifiers []cautils.PolicyIdentifier
	if policy.Frameworks != nil {
		identifiers = cautils.AppendPolicyIdentifiers(identifiers, *policy.Frameworks, apisv1.KindFramework)
	}
	if policy.Controls != nil {
		identifiers = cautils.AppendPolicyIdentifiers(identifiers, *policy.Controls, apisv1.KindControl)
	}
	return identifiers
}
