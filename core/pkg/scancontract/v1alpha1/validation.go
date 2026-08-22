package v1alpha1

import (
	"fmt"
	"math"
	"slices"
	"strings"

	"golang.org/x/mod/semver"
	k8svalidation "k8s.io/apimachinery/pkg/util/validation"
)

func validateVersionEnvelope(apiVersion, kind, minimumVersion, runningVersion string) error {
	if apiVersion != APIVersion {
		return fmt.Errorf("unsupported apiVersion %q: this Kubescape build supports %q", apiVersion, APIVersion)
	}
	if kind != Kind {
		return fmt.Errorf("unsupported kind %q: expected %q", kind, Kind)
	}
	if !semver.IsValid(minimumVersion) {
		return fmt.Errorf("spec.minimumKubescapeVersion %q is not a valid semantic version", minimumVersion)
	}
	if !semver.IsValid(runningVersion) {
		// Development and other non-release builds use values such as "dev",
		// "unknown", or "(devel)". There is no meaningful ordering for those
		// identifiers, so validate the contract schema but skip compatibility.
		return nil
	}
	if semver.Compare(runningVersion, minimumVersion) < 0 {
		return fmt.Errorf("contract requires Kubescape %s or newer; running %s", minimumVersion, runningVersion)
	}
	return nil
}

func validateDocument(document *Document, options LoadOptions) error {
	if document.Metadata.Name == "" {
		return fmt.Errorf("metadata.name is required")
	}
	if problems := k8svalidation.IsDNS1123Label(document.Metadata.Name); len(problems) > 0 {
		return fmt.Errorf("metadata.name %q is invalid: %s", document.Metadata.Name, strings.Join(problems, "; "))
	}
	if len(document.Spec.Contracts) == 0 {
		return fmt.Errorf("spec.contracts must contain at least one named contract")
	}
	if document.Spec.DefaultContract != "" {
		if _, ok := document.Spec.Contracts[document.Spec.DefaultContract]; !ok {
			return fmt.Errorf("spec.defaultContract %q does not name an entry in spec.contracts", document.Spec.DefaultContract)
		}
	}
	for name, contract := range document.Spec.Contracts {
		if problems := k8svalidation.IsDNS1123Label(name); len(problems) > 0 {
			return fmt.Errorf("spec.contracts key %q is invalid: %s", name, strings.Join(problems, "; "))
		}
		if err := validateContract(name, contract, options); err != nil {
			return err
		}
	}
	return nil
}

func validateContract(name string, contract Contract, options LoadOptions) error {
	prefix := fmt.Sprintf("spec.contracts.%s", name)
	if contract.Policy != nil {
		if err := validateStringList(prefix+".policy.frameworks", contract.Policy.Frameworks); err != nil {
			return err
		}
		if err := validateStringList(prefix+".policy.controls", contract.Policy.Controls); err != nil {
			return err
		}
		if contract.Policy.ControlsVersion != nil {
			value := strings.TrimSpace(*contract.Policy.ControlsVersion)
			if value == "" {
				return fmt.Errorf("%s.policy.controlsVersion cannot be empty", prefix)
			}
			if strings.Contains(value, "/") {
				return fmt.Errorf("%s.policy.controlsVersion %q cannot contain '/'", prefix, value)
			}
		}
	}
	if contract.Scope != nil {
		if err := validateStringList(prefix+".scope.includeNamespaces", contract.Scope.IncludeNamespaces); err != nil {
			return err
		}
		if err := validateStringList(prefix+".scope.excludeNamespaces", contract.Scope.ExcludeNamespaces); err != nil {
			return err
		}
		if contract.Scope.IncludeNamespaces != nil && len(*contract.Scope.IncludeNamespaces) > 0 &&
			contract.Scope.ExcludeNamespaces != nil && len(*contract.Scope.ExcludeNamespaces) > 0 {
			return fmt.Errorf("%s.scope.includeNamespaces and excludeNamespaces cannot both be set", prefix)
		}
	}
	if contract.Evaluation != nil {
		if contract.Evaluation.ScanTimeout != nil && contract.Evaluation.ScanTimeout.Duration < 0 {
			return fmt.Errorf("%s.evaluation.scanTimeout must be zero or positive", prefix)
		}
		if contract.Evaluation.ControlTimeout != nil && contract.Evaluation.ControlTimeout.Duration < 0 {
			return fmt.Errorf("%s.evaluation.controlTimeout must be zero or positive", prefix)
		}
		if contract.Evaluation.ScanTimeout != nil && contract.Evaluation.ControlTimeout != nil &&
			contract.Evaluation.ScanTimeout.Duration > 0 && contract.Evaluation.ControlTimeout.Duration >= contract.Evaluation.ScanTimeout.Duration {
			return fmt.Errorf("%s.evaluation.controlTimeout must be lower than scanTimeout when both are set", prefix)
		}
	}
	if contract.Failure != nil {
		if contract.Failure.SeverityAtLeast != nil {
			severity := strings.TrimSpace(*contract.Failure.SeverityAtLeast)
			if !containsFold(options.SupportedSeverities, severity) {
				return fmt.Errorf("%s.failure.severityAtLeast %q is unsupported; supported severities: %s", prefix, severity, strings.Join(options.SupportedSeverities, ", "))
			}
		}
		if err := validatePercentage(prefix+".failure.complianceBelow", contract.Failure.ComplianceBelow); err != nil {
			return err
		}
		if err := validatePercentage(prefix+".failure.coverageBelow", contract.Failure.CoverageBelow); err != nil {
			return err
		}
		if contract.Failure.DegradedPolicyInput != nil &&
			*contract.Failure.DegradedPolicyInput != DegradedPolicyInputAllow &&
			*contract.Failure.DegradedPolicyInput != DegradedPolicyInputFail {
			return fmt.Errorf("%s.failure.degradedPolicyInput %q is unsupported; supported values: allow, fail", prefix, *contract.Failure.DegradedPolicyInput)
		}
	}
	if contract.Output != nil {
		if err := validateStringList(prefix+".output.formats", contract.Output.Formats); err != nil {
			return err
		}
		if contract.Output.Formats != nil {
			for _, format := range *contract.Output.Formats {
				if !slices.Contains(options.SupportedFormats, format) {
					return fmt.Errorf("%s.output.formats contains unsupported format %q; supported formats: %s", prefix, format, strings.Join(options.SupportedFormats, ", "))
				}
			}
		}
	}
	return nil
}

func validateStringList(path string, values *[]string) error {
	if values == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(*values))
	for _, value := range *values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			return fmt.Errorf("%s contains an empty value", path)
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			return fmt.Errorf("%s contains duplicate value %q", path, value)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validatePercentage(path string, value *float64) error {
	if value == nil {
		return nil
	}
	if math.IsNaN(*value) || math.IsInf(*value, 0) || *value < 0 || *value > 100 {
		return fmt.Errorf("%s must be between 0 and 100", path)
	}
	return nil
}

func containsFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}
