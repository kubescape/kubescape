package vap

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/opaprocessor/cel"
	"github.com/spf13/cobra"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"
)

var vapHelperCmdExamples = fmt.Sprintf(`
  vap command can be used for managing Validating Admission Policies in a Kubernetes cluster.
  This is an experimental feature and it might change.

  Examples:

  # Install Kubescape CEL admission policy library (the copy embedded in this binary)
  %[1]s vap deploy-library | kubectl apply -f -
  # Install a specific cel-admission-library release instead of the embedded copy
  %[1]s vap deploy-library --from-release v0.11 | kubectl apply -f -
  # Create a policy binding by Kubescape control ID
  %[1]s vap create-policy-binding --name my-policy-binding --control C-0016 --namespace=my-namespace | kubectl apply -f -
  # Create a policy binding by ValidatingAdmissionPolicy name
  %[1]s vap create-policy-binding --name my-policy-binding --policy kubescape-c-0016-allow-privilege-escalation --namespace=my-namespace | kubectl apply -f -
  # Roll a control out in report-only mode before switching it to Deny
  %[1]s vap create-policy-binding --name my-policy-binding --control C-0016 --action Audit --action Warn | kubectl apply -f -
  # Narrow a policy binding to specific resources, including custom ones
  %[1]s vap create-policy-binding --name my-policy-binding --control C-0016 --resource-rule apps/v1/deployments --resource-rule /v1/pods | kubectl apply -f -
`, cautils.ExecName())

func GetVapHelperCmd() *cobra.Command {

	vapHelperCmd := &cobra.Command{
		Use:     "vap",
		Short:   "Helper commands for managing Validating Admission Policies in a Kubernetes cluster",
		Long:    ``,
		Example: vapHelperCmdExamples,
	}

	// Create subcommands
	vapHelperCmd.AddCommand(getDeployLibraryCmd())
	vapHelperCmd.AddCommand(getCreatePolicyBindingCmd())

	return vapHelperCmd
}

// defaultDownloadTimeout bounds each --from-release download. It matches the
// 30s used by the other outbound HTTP clients in the codebase (the repository
// scanner and the cluster connector).
const defaultDownloadTimeout = 30 * time.Second

func getDeployLibraryCmd() *cobra.Command {
	var outputFile string
	var fromRelease string
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:   "deploy-library",
		Short: "Install Kubescape CEL admission policy library",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			content, err := deployLibrary(fromRelease, timeout)
			if err != nil {
				return err
			}
			return writeOutput(content, outputFile)
		},
	}
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write output to file instead of stdout")
	cmd.Flags().StringVar(&fromRelease, "from-release", "", "Download the library from this cel-admission-library release tag (e.g. v0.11) instead of using the embedded copy")
	cmd.Flags().DurationVar(&timeout, "timeout", defaultDownloadTimeout, "HTTP request timeout per download, only used with --from-release (e.g. 30s, 1m). 0 disables the timeout")

	return cmd
}

func getCreatePolicyBindingCmd() *cobra.Command {
	var policyBindingName string
	var policyName string
	var controlID string
	var namespaceArr []string
	var labelArr []string
	var actionArr []string
	var resourceRuleArr []string
	var parameterReference string
	var outputFile string

	createPolicyBindingCmd := &cobra.Command{
		Use:   "create-policy-binding",
		Short: "Create a policy binding",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate the inputs
			if err := isValidK8sObjectName(policyBindingName); err != nil {
				return fmt.Errorf("invalid policy binding name %s: %w", policyBindingName, err)
			}
			resolvedPolicyName, err := resolvePolicyName(policyName, controlID)
			if err != nil {
				return err
			}
			// A policy that declares a paramKind needs a ParamRef on its binding
			// to be functional, so refuse to emit a silently broken binding. The
			// check covers both flags: --control reads the paramKind off the
			// control's policy, --policy off the named policy (a name outside
			// the embedded bundle is left unchecked — we know nothing about it).
			normalizedControlID := strings.ToUpper(strings.TrimSpace(controlID))
			if parameterReference == "" {
				if normalizedControlID != "" {
					paramKind, err := cel.ParamKindForControl(normalizedControlID)
					if err != nil {
						return err
					}
					if paramKind != nil {
						return fmt.Errorf("control %s requires --parameter-reference because its CEL policy uses params", normalizedControlID)
					}
				} else {
					paramKind, found, err := cel.ParamKindForPolicy(resolvedPolicyName)
					if err != nil {
						return err
					}
					if found && paramKind != nil {
						return fmt.Errorf("policy %s requires --parameter-reference because it uses params", resolvedPolicyName)
					}
				}
			}
			if err := isValidK8sObjectName(resolvedPolicyName); err != nil {
				return fmt.Errorf("invalid policy name %s: %w", resolvedPolicyName, err)
			}
			if err := checkResourceRulesInPolicyScope(resourceRuleArr, normalizedControlID, resolvedPolicyName); err != nil {
				return err
			}
			for _, namespace := range namespaceArr {
				if err := isValidNamespace(namespace); err != nil {
					return fmt.Errorf("invalid namespace %s: %w", namespace, err)
				}
			}
			if _, err := parseObjectSelectorLabels(labelArr); err != nil {
				return err
			}
			actions, err := parseValidationActions(actionArr)
			if err != nil {
				return err
			}
			if parameterReference != "" {
				if err := isValidK8sObjectName(parameterReference); err != nil {
					return fmt.Errorf("invalid parameter reference %s: %w", parameterReference, err)
				}
			}

			content, err := createPolicyBinding(policyBindingName, resolvedPolicyName, actions, parameterReference, namespaceArr, labelArr, resourceRuleArr)
			if err != nil {
				return err
			}
			return writeOutput(content, outputFile)
		},
	}
	// Must specify the name of the policy binding
	createPolicyBindingCmd.Flags().StringVarP(&policyBindingName, "name", "n", "", "Name of the policy binding")
	_ = createPolicyBindingCmd.MarkFlagRequired("name") // #nosec G104 -- flag is defined on this command; MarkFlagRequired only errors for an unknown flag
	createPolicyBindingCmd.Flags().StringVarP(&policyName, "policy", "p", "", "Name of the ValidatingAdmissionPolicy to bind resources to")
	createPolicyBindingCmd.Flags().StringVarP(&controlID, "control", "c", "", "Kubescape control ID to bind resources to")
	createPolicyBindingCmd.Flags().StringSliceVar(&namespaceArr, "namespace", []string{}, "Resource namespace selector")
	createPolicyBindingCmd.Flags().StringSliceVar(&labelArr, "label", []string{}, "Resource label selector")
	createPolicyBindingCmd.Flags().StringSliceVarP(&actionArr, "action", "a", []string{string(admissionv1.Deny)}, "Action to take when policy fails, repeatable (Deny, Warn, Audit). Deny and Warn cannot be combined")
	createPolicyBindingCmd.Flags().StringSliceVar(&resourceRuleArr, "resource-rule", []string{}, "Restrict the binding to a group/version/resource the policy already matches, repeatable (e.g. apps/v1/deployments, /v1/pods). Omit to bind everything the policy matches")
	createPolicyBindingCmd.Flags().StringVarP(&parameterReference, "parameter-reference", "r", "", "Parameter reference object name")
	createPolicyBindingCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write output to file instead of stdout")

	return createPolicyBindingCmd
}

// resolvePolicyName resolves the --policy/--control pair to a policy name.
// Control IDs resolve against the VAP bundle embedded in the CEL engine, so the
// answer always matches the deployable YAML instead of a hand-maintained copy.
// Policy names are lowercased like control IDs are uppercased: both flags then
// accept any casing of their canonical form.
func resolvePolicyName(policyName, controlID string) (string, error) {
	policyName = strings.ToLower(strings.TrimSpace(policyName))
	controlID = strings.ToUpper(strings.TrimSpace(controlID))

	if policyName == "" && controlID == "" {
		return "", fmt.Errorf("either --policy or --control must be specified")
	}
	if policyName != "" && controlID != "" {
		return "", fmt.Errorf("only one of --policy or --control can be specified")
	}
	if policyName != "" {
		return policyName, nil
	}

	resolved, err := cel.PolicyNameForControl(controlID)
	if err != nil {
		return "", fmt.Errorf("unsupported control ID %s: %w", controlID, err)
	}
	return resolved, nil
}

// Implementation of the VAP helper commands
// deploy-library
//
// By default the library comes from the bundle embedded in this binary: the
// same copy the scan engine evaluates and create-policy-binding resolves
// metadata from, so what gets deployed is exactly what this build was tested
// against. Downloading a release instead is an explicit opt-in via
// --from-release; it can serve a library this binary knows nothing about, so
// it is never the silent default (issue #2507).
func deployLibrary(fromRelease string, timeout time.Duration) (string, error) {
	if fromRelease != "" {
		return downloadLibrary(fromRelease, timeout)
	}
	return cel.EmbeddedLibraryYAML()
}

// libraryReleaseFiles are the release assets that make up the deployable
// library, in apply order (the CRD first, then the configuration, then the
// policies). Must stay in sync with the assets `make sync-vap` vendors.
var libraryReleaseFiles = []string{
	"policy-configuration-definition.yaml",
	"basic-control-configuration.yaml",
	"kubescape-validating-admission-policies.yaml",
}

// releaseTagPattern is the shape a cel-admission-library release tag may take.
// It is deliberately an allowlist: the tag is interpolated into the release
// URL, so any character that carries meaning in a URL path has to stay out.
// Requiring an alphanumeric first character also rules out "." and ".." on its
// own. Real tags ("v0.11") and the usual semver decorations ("v1.2.3-rc1",
// "v1.2.3+build.5") all satisfy it.
var releaseTagPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)

// validateReleaseTag rejects a tag that would change the shape of the release
// URL rather than just name a release within it. Without this the tag can walk
// out of the kubescape release path entirely ("../../../../owner/repo/..."):
// Go's HTTP client forwards the "../" segments verbatim and GitHub resolves
// them server-side, so the library is served from an unrelated repository while
// the log line still names the requested kubescape release. A "?" or "#" is the
// same class of bug without an attacker - it truncates the URL, so every file
// in libraryReleaseFiles resolves to the same object and the concatenated
// output is silently wrong.
func validateReleaseTag(tag string) error {
	if !releaseTagPattern.MatchString(tag) {
		return fmt.Errorf("invalid release tag %q: expected a release tag such as v0.11", tag)
	}
	return nil
}

// downloadLibrary fetches the library files from one pinned release tag and
// concatenates them into a single multi-document YAML stream. The tag is
// always explicit — downloading whatever "latest" points at would reintroduce
// the skew deployLibrary's embedded default exists to prevent.
func downloadLibrary(tag string, timeout time.Duration) (string, error) {
	if err := validateReleaseTag(tag); err != nil {
		return "", err
	}

	logger.L().Info(fmt.Sprintf("Downloading the Kubescape CEL admission policy library release %s", tag))

	parts := make([]string, 0, len(libraryReleaseFiles))
	for _, file := range libraryReleaseFiles {
		url := fmt.Sprintf("https://github.com/kubescape/cel-admission-library/releases/download/%s/%s", tag, file)
		content, err := downloadFileToString(url, timeout)
		if err != nil {
			return "", fmt.Errorf("download %s from release %s: %w", file, tag, err)
		}
		parts = append(parts, content)
	}

	logger.L().Info("Successfully downloaded admission policy library")
	return strings.Join(parts, "\n---\n") + "\n", nil
}

func downloadFileToString(url string, timeout time.Duration) (string, error) {
	client := &http.Client{
		Timeout: timeout,
	}
	response, err := client.Get(url)
	if err != nil {
		return "", err // Return an empty string and the error if the request fails
	}
	defer response.Body.Close()

	// Check for a successful response (HTTP 200 OK)
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to download file: %s", response.Status)
	}

	// Read the response body
	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err // Return an empty string and the error if reading fails
	}

	// Convert the byte slice to a string
	bodyString := string(bodyBytes)
	return bodyString, nil
}

func writeOutput(content string, outputFile string) error {
	if outputFile != "" {
		if err := os.MkdirAll(filepath.Dir(outputFile), 0750); err != nil {
			return err
		}
		return os.WriteFile(outputFile, []byte(content), 0600)
	}
	fmt.Print(content)
	return nil
}

func isValidK8sObjectName(name string) error {
	if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 {
		return fmt.Errorf("invalid name: %s", strings.Join(errs, "; "))
	}
	return nil
}

func isValidNamespace(name string) error {
	if errs := validation.IsDNS1123Label(name); len(errs) > 0 {
		return fmt.Errorf("invalid namespace: %s", strings.Join(errs, "; "))
	}
	return nil
}

// supportedValidationActions are the enforcement actions the admission API
// accepts on a binding, matched case-sensitively as the API spells them.
var supportedValidationActions = []admissionv1.ValidationAction{
	admissionv1.Deny,
	admissionv1.Warn,
	admissionv1.Audit,
}

// parseValidationActions turns the --action values into the binding's
// validationActions set. The field is a set on the API, so a binding can carry
// more than one action — the usual rollout is Audit plus Warn first and Deny
// once the findings are clean, which a single-valued flag could not express.
//
// The two combinations the apiserver rejects are refused here rather than at
// apply time: a repeated action (the field is a listType=set) and Deny with
// Warn, which the API forbids because it would report the same failure twice.
// Order is preserved so the emitted YAML reads back the way it was asked for.
func parseValidationActions(values []string) ([]admissionv1.ValidationAction, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("at least one --action is required")
	}
	actions := make([]admissionv1.ValidationAction, 0, len(values))
	seen := make(map[admissionv1.ValidationAction]struct{}, len(values))
	for _, value := range values {
		action := admissionv1.ValidationAction(strings.TrimSpace(value))
		if !isSupportedValidationAction(action) {
			return nil, fmt.Errorf("invalid action: %s", value)
		}
		if _, dup := seen[action]; dup {
			return nil, fmt.Errorf("duplicate action: %s", action)
		}
		seen[action] = struct{}{}
		actions = append(actions, action)
	}
	if _, deny := seen[admissionv1.Deny]; deny {
		if _, warn := seen[admissionv1.Warn]; warn {
			return nil, fmt.Errorf("actions Deny and Warn cannot be combined")
		}
	}
	return actions, nil
}

func isSupportedValidationAction(action admissionv1.ValidationAction) bool {
	for _, supported := range supportedValidationActions {
		if action == supported {
			return true
		}
	}
	return false
}

// parseObjectSelectorLabels turns the --label values into the matchLabels of
// the binding's objectSelector. The flag validation and the emitted binding
// both read the labels through here, so what the command accepts and what it
// writes cannot drift apart.
//
// Only equality selectors are accepted: matchLabels is an equality map, so an
// Exists or In requirement has nowhere to go on the binding. "=" and "==" are
// distinct operators in apimachinery but mean the same thing, so both pass.
func parseObjectSelectorLabels(values []string) (map[string]string, error) {
	matchLabels := make(map[string]string, len(values))
	for _, value := range values {
		parsed, err := labels.Parse(value)
		if err != nil {
			return nil, fmt.Errorf("invalid label selector: %s", value)
		}
		requirements, _ := parsed.Requirements()
		for _, requirement := range requirements {
			if requirement.Operator() != selection.Equals && requirement.Operator() != selection.DoubleEquals {
				return nil, fmt.Errorf("only equality label selectors ('=' or '==') are supported: %s", value)
			}
			// An equality requirement carries exactly one value; anything else
			// is refused rather than skipped, so no label can go missing from
			// the selector without the command saying so.
			selected := requirement.Values().List()
			if len(selected) != 1 {
				return nil, fmt.Errorf("label selector %s must name exactly one value", value)
			}
			matchLabels[requirement.Key()] = selected[0]
		}
	}
	return matchLabels, nil
}

// resourceRuleParts is the group/version/resource form of --resource-rule. The
// resource keeps any subresource, so "apps/v1/deployments/scale" still splits
// into three.
const resourceRuleParts = 3

// parseResourceRule turns a "group/version/resource" value into a rule for the
// binding's matchResources. The core group is the empty first segment
// ("/v1/pods") and "*" is accepted in any segment.
//
// Operations stay at "*" because a binding intersects with the policy's
// matchConstraints, which already declares the operations the policy cares
// about; narrowing them here could only drop matches the policy intends.
func parseResourceRule(rule string) (admissionv1.NamedRuleWithOperations, error) {
	parts := strings.SplitN(strings.TrimSpace(rule), "/", resourceRuleParts)
	if len(parts) != resourceRuleParts {
		return admissionv1.NamedRuleWithOperations{}, fmt.Errorf("invalid resource rule %q: expected group/version/resource, e.g. apps/v1/deployments or /v1/pods for the core group", rule)
	}
	group, version, resource := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2])
	if version == "" || resource == "" {
		return admissionv1.NamedRuleWithOperations{}, fmt.Errorf("invalid resource rule %q: version and resource are required", rule)
	}
	// The group is the one segment allowed to be empty: that is how the core
	// group is spelled, both here and on the resulting rule.
	if group != "" {
		if err := validateRuleSegment("api group", group, validation.IsDNS1123Subdomain); err != nil {
			return admissionv1.NamedRuleWithOperations{}, err
		}
	}
	if err := validateRuleSegment("api version", version, validation.IsDNS1123Label); err != nil {
		return admissionv1.NamedRuleWithOperations{}, err
	}
	// A resource may carry a subresource ("deployments/scale"); each side is a
	// plain name on its own.
	for _, segment := range strings.Split(resource, "/") {
		if err := validateRuleSegment("resource", segment, validation.IsDNS1123Label); err != nil {
			return admissionv1.NamedRuleWithOperations{}, err
		}
	}
	return admissionv1.NamedRuleWithOperations{
		RuleWithOperations: admissionv1.RuleWithOperations{
			Operations: []admissionv1.OperationType{admissionv1.OperationAll},
			Rule: admissionv1.Rule{
				APIGroups:   []string{group},
				APIVersions: []string{version},
				Resources:   []string{resource},
			},
		},
	}, nil
}

// validateRuleSegment checks one segment of a resource rule, accepting the "*"
// wildcard the admission API allows in any of them.
func validateRuleSegment(kind string, value string, validate func(string) []string) error {
	if value == "*" {
		return nil
	}
	if errs := validate(value); len(errs) > 0 {
		return fmt.Errorf("invalid %s %q: %s", kind, value, strings.Join(errs, "; "))
	}
	return nil
}

// checkResourceRulesInPolicyScope refuses a --resource-rule the bound policy can
// never match. The apiserver intersects a binding's matchResources with the
// policy's matchConstraints, so a rule outside them applies cleanly and enforces
// nothing.
//
// The lookup mirrors the paramKind check: --control reads the constraints off
// the control's policy, --policy off the named one. A policy we know nothing
// about — a name outside the embedded bundle, or one declaring no resource
// rules — is left unchecked rather than blocked.
func checkResourceRulesInPolicyScope(rules []string, controlID, policyName string) error {
	if len(rules) == 0 {
		return nil
	}
	constraints, err := policyMatchConstraints(controlID, policyName)
	if err != nil {
		return err
	}
	if constraints == nil || len(constraints.ResourceRules) == 0 {
		return nil
	}
	for _, rule := range rules {
		parsed, err := parseResourceRule(rule)
		if err != nil {
			return err
		}
		switch classifyResourceRule(parsed, constraints.ResourceRules) {
		case ruleOutsidePolicy:
			return fmt.Errorf("resource rule %q is outside the matchConstraints of policy %s, so the binding would match nothing; the policy matches %s",
				strings.TrimSpace(rule), policyName, describeResourceRules(constraints.ResourceRules))
		case ruleConvertsToPolicy:
			logger.L().Warning("resource rule names another API group or version than the policy constrains; the binding matches only if the cluster serves them as equivalent forms of one resource",
				helpers.String("rule", strings.TrimSpace(rule)),
				helpers.String("policy", policyName),
				helpers.String("policyMatches", describeResourceRules(constraints.ResourceRules)))
		}
	}
	return nil
}

// policyMatchConstraints resolves the bound policy's matchConstraints, nil when
// there are none to check a rule against.
func policyMatchConstraints(controlID, policyName string) (*admissionv1.MatchResources, error) {
	if controlID != "" {
		return cel.MatchConstraintsForControl(controlID)
	}
	constraints, found, err := cel.MatchConstraintsForPolicy(policyName)
	if err != nil || !found {
		return nil, err
	}
	return constraints, nil
}

// resourceRuleScope is what this command can conclude offline about one
// --resource-rule, given the policy it is being bound to.
type resourceRuleScope int

const (
	// ruleOutsidePolicy: the policy constrains no resource the rule names, which
	// no API conversion can bridge. The binding would match nothing.
	ruleOutsidePolicy resourceRuleScope = iota
	// ruleConvertsToPolicy: the policy constrains the resource, but at another
	// API group or version. Whether those are equivalent forms of one resource
	// is a cluster fact, so this is reported rather than refused.
	ruleConvertsToPolicy
	// ruleMatchesPolicy: the rule names a resource the policy constrains, at the
	// same group and version.
	ruleMatchesPolicy
)

// classifyResourceRule compares a binding rule against the policy's resource
// rules. Only a resource mismatch is conclusive offline.
//
// A group or version mismatch is not, because matchResources defaults to
// matchPolicy Equivalent and this command never sets it: the emitted binding
// matches a request for the resource even when it arrives via another group or
// version, so a rule naming apps/v1beta1/deployments still intersects a policy
// constraining apps/v1/deployments. Which forms are equivalent is something only
// the cluster knows, so the two cannot be told apart from a typo here. The
// policy's own matchPolicy does not change this — the binding side alone is
// enough to bridge the gap. A resource name, by contrast, is stable across
// equivalent forms, and conversion never turns a subresource into a resource.
//
// excludeResourceRules are not consulted: they carve out part of a surface
// rather than define it. Operations and scope are not compared either, since a
// parsed --resource-rule always carries "*" for both.
func classifyResourceRule(rule admissionv1.NamedRuleWithOperations, constraints []admissionv1.NamedRuleWithOperations) resourceRuleScope {
	scope := ruleOutsidePolicy
	for i := range constraints {
		constraint := &constraints[i]
		if !resourcesOverlap(rule.Resources, constraint.Resources) {
			continue
		}
		if valuesOverlap(rule.APIGroups, constraint.APIGroups) &&
			valuesOverlap(rule.APIVersions, constraint.APIVersions) {
			return ruleMatchesPolicy
		}
		scope = ruleConvertsToPolicy
	}
	return scope
}

func valuesOverlap(a, b []string) bool {
	for _, want := range a {
		for _, have := range b {
			if valueMatches(want, have) {
				return true
			}
		}
	}
	return false
}

// resourcesOverlap is valuesOverlap for resources, honoring the subresource form
// the admission API uses: "pods" and "pods/exec" are separate surfaces, "*"
// covers every resource but no subresource, and "*/*" covers both.
func resourcesOverlap(a, b []string) bool {
	for _, want := range a {
		wantResource, wantSubresource := splitSubresource(want)
		for _, have := range b {
			haveResource, haveSubresource := splitSubresource(have)
			if valueMatches(wantResource, haveResource) && valueMatches(wantSubresource, haveSubresource) {
				return true
			}
		}
	}
	return false
}

func splitSubresource(resource string) (string, string) {
	if name, subresource, found := strings.Cut(resource, "/"); found {
		return name, subresource
	}
	return resource, ""
}

func valueMatches(a, b string) bool {
	return a == "*" || b == "*" || a == b
}

// describeResourceRules renders a policy's resource rules in the
// group/version/resource form --resource-rule takes, so the refusal names what
// the flag would have to say instead.
func describeResourceRules(rules []admissionv1.NamedRuleWithOperations) string {
	seen := make(map[string]struct{})
	described := make([]string, 0, len(rules))
	for i := range rules {
		for _, group := range rules[i].APIGroups {
			for _, version := range rules[i].APIVersions {
				for _, resource := range rules[i].Resources {
					entry := strings.Join([]string{group, version, resource}, "/")
					if _, duplicate := seen[entry]; duplicate {
						continue
					}
					seen[entry] = struct{}{}
					described = append(described, entry)
				}
			}
		}
	}
	return strings.Join(described, ", ")
}

// Create a policy binding
func createPolicyBinding(bindingName string, policyName string, actions []admissionv1.ValidationAction, paramRefName string, namespaceArr []string, labelMatch []string, resourceRuleArr []string) (string, error) {
	// Create a policy binding struct
	policyBinding := &admissionv1.ValidatingAdmissionPolicyBinding{}
	policyBinding.APIVersion = "admissionregistration.k8s.io/v1"
	policyBinding.Name = bindingName
	policyBinding.Kind = "ValidatingAdmissionPolicyBinding"
	policyBinding.Spec.PolicyName = policyName
	policyBinding.Spec.MatchResources = &admissionv1.MatchResources{}
	if len(namespaceArr) > 0 {
		policyBinding.Spec.MatchResources.NamespaceSelector = &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      "kubernetes.io/metadata.name",
					Operator: metav1.LabelSelectorOpIn,
					Values:   namespaceArr,
				},
			},
		}
	}

	matchLabels, err := parseObjectSelectorLabels(labelMatch)
	if err != nil {
		return "", err
	}
	if len(labelMatch) > 0 {
		policyBinding.Spec.MatchResources.ObjectSelector = &metav1.LabelSelector{MatchLabels: matchLabels}
	}

	// Left empty, matchResources binds everything the policy matches, so a rule
	// is only emitted when the caller asked to narrow it.
	for _, rule := range resourceRuleArr {
		parsed, err := parseResourceRule(rule)
		if err != nil {
			return "", err
		}
		policyBinding.Spec.MatchResources.ResourceRules = append(policyBinding.Spec.MatchResources.ResourceRules, parsed)
	}

	policyBinding.Spec.ValidationActions = actions
	paramAction := admissionv1.DenyAction
	if paramRefName != "" {
		policyBinding.Spec.ParamRef = &admissionv1.ParamRef{
			Name:                    paramRefName,
			ParameterNotFoundAction: &paramAction,
		}
	}
	// Marshal the policy binding to YAML
	out, err := yaml.Marshal(policyBinding)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
