package opaprocessor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/kubescape/opa-utils/resources"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

// Parity harness for the Rego-to-CEL migration.
//
// A control that has been converted now has two implementations: the Rego rules
// regolibrary still ships, and the ValidatingAdmissionPolicy the CEL bundle
// ships. Nothing in the tree checked that they say the same thing. This runs
// both over the same objects and compares them.
//
// Both sides go through processRule, so the only difference between the two
// runs is the rule's language. That keeps enumeration, namespace filtering and
// pass-inference identical and leaves the evaluation itself as the only place a
// disagreement can come from.
//
// It compares verdicts and nothing else. Remediation paths are deliberately out
// of scope: the two engines describe a failure differently on purpose (Rego
// yields failedPaths per matching term, the CEL side yields hints off the
// expression), and so are risk-score denominators, which count resources rather
// than assess them.
//
// The fixtures are regolibrary's own rule tests, vendored under
// testdata/regocelparity — see the README there for what is copied and why.
//
// Each side is configured the way a scan configures it, which means from
// different files: the Rego rules read the postureControlInputs regolibrary
// ships, and the CEL policies read the ControlConfiguration make sync-vap
// vendors. Handing both the same settings would be a tidier experiment and a
// less useful one, because configuration that has drifted between the two
// libraries changes scan results just as surely as an expression that has.

const (
	regoCELParityDir      = "testdata/regocelparity"
	regoCELParityRulesDir = regoCELParityDir + "/rules"

	// regoCELParityConfigPath is regolibrary's default-config-inputs.json,
	// vendored alongside the rules. It is what a scan feeds the Rego side when
	// the customer has not overridden anything.
	regoCELParityConfigPath = regoCELParityDir + "/default-config-inputs.json"

	// regoCELParityLibraryVersion is the regolibrary tag testdata/regocelparity
	// was copied from. Kept next to the harness so a refresh that forgets to
	// update the README is still recorded somewhere the test reads.
	regoCELParityLibraryVersion = "v2.0.33"
)

// psaNamespaceSubject is the reason the Pod Security Admission controls are not
// expected to agree. Their Rego rules read the enforcing Namespace's
// pod-security.kubernetes.io/enforce label and fail the Namespace; the CEL
// policies check the workload the CIS item is actually about. Different subject,
// so the two sides do not report on the same resources, and regolibrary's
// Namespace fixtures never reach the CEL policy at all. This is a decision, not
// an unfinished conversion, and it is one divergence repeated across seven
// controls rather than seven of them.
const psaNamespaceSubject = "the Rego rule fails the Namespace on its PSA enforce label; the CEL policy checks the workload"

// regoCELControl pairs a control with the regolibrary rules it runs.
type regoCELControl struct {
	controlID string
	// rules are directory names under regoCELParityRulesDir. A control fails a
	// resource when any of them fails it, which is how processControl folds a
	// multi-rule control together.
	rules []string
	// divergence, when set, says why this control's two implementations do not
	// agree. Such a control is still evaluated on both sides, and is required to
	// actually disagree somewhere: an entry that has gone stale is a worse
	// outcome than one that was never written.
	divergence string
	// gap marks a divergence that is a defect rather than a decision — the CEL
	// side is meant to match the Rego and does not yet. The fix belongs in
	// cel-admission-library and never here, so an entry stands until a pin bump
	// brings the corrected policy in and this test starts failing for the
	// opposite reason. Empty of gaps is the goal.
	gap bool
}

// regoCELParityControls covers the controls that ship as both a Rego rule set
// and a CEL policy. The rule lists come from rulesNames in each control's
// regolibrary JSON, which is authoritative — ControlID_RuleName.csv covers only
// part of the library and is missing most of these.
//
// C-0081 (CVE-2022-24348) is converted but absent: regolibrary ships no rule
// tests for it, so there is nothing to feed either engine. Covering it needs
// hand-written fixtures, which is a different argument from "regolibrary's own
// cases agree", so it belongs in its own change.
var regoCELParityControls = []regoCELControl{
	{
		controlID: "C-0012",
		rules:     []string{"rule-credentials-in-env-var", "rule-credentials-configmap"},
		gap:       true,
		divergence: "three things the Rego does and the CEL policy does not: it excuses a value that is a " +
			"file path (is_not_file_path), it matches sensitiveValues case-insensitively via (?i), and " +
			"the bundle's ControlConfiguration is missing four of the sensitiveValues regexes regolibrary " +
			"ships (AKIA, AIza, ghp_, xox)",
	},
	{
		controlID:  "C-0013",
		rules:      []string{"non-root-containers"},
		gap:        true,
		divergence: "the CEL policy also requires allowPrivilegeEscalation=false, which non-root-containers does not check; a container that is non-root but silent on escalation passes the Rego and fails the policy",
	},
	{controlID: "C-0193", rules: psaBaselineRules, divergence: psaNamespaceSubject},
	{controlID: "C-0194", rules: psaBaselineRules, divergence: psaNamespaceSubject},
	{controlID: "C-0195", rules: psaBaselineRules, divergence: psaNamespaceSubject},
	{controlID: "C-0197", rules: []string{
		"pod-security-admission-restricted-applied-1",
		"pod-security-admission-restricted-applied-2",
	}, divergence: psaNamespaceSubject},
	{controlID: "C-0202", rules: psaBaselineRules, divergence: psaNamespaceSubject},
	{controlID: "C-0203", rules: psaBaselineRules, divergence: psaNamespaceSubject},
	{controlID: "C-0204", rules: psaBaselineRules, divergence: psaNamespaceSubject},
	{controlID: "C-0207", rules: []string{"rule-secrets-in-env-var"}},
	{
		controlID: "C-0212",
		gap:       true,
		divergence: "the Rego exempts the kubernetes Service and Endpoints the apiserver creates in the " +
			"default namespace, which CIS 5.7.4 excludes (regolibrary#644); the CEL policy has no such " +
			"exemption, so it fails two resources every cluster has",
		rules: []string{
			// One control fanning out to seventeen rules, one per kind that must not
			// live in the default namespace. Its verdict is the OR over all of them.
			"pods-in-default-namespace",
			"rolebinding-in-default-namespace",
			"role-in-default-namespace",
			"configmap-in-default-namespace",
			"endpoints-in-default-namespace",
			"persistentvolumeclaim-in-default-namespace",
			"podtemplate-in-default-namespace",
			"replicationcontroller-in-default-namespace",
			"service-in-default-namespace",
			"serviceaccount-in-default-namespace",
			"endpointslice-in-default-namespace",
			"horizontalpodautoscaler-in-default-namespace",
			"lease-in-default-namespace",
			"csistoragecapacity-in-default-namespace",
			"ingress-in-default-namespace",
			"poddisruptionbudget-in-default-namespace",
			"resources-secret-in-default-namespace",
		}},
	{controlID: "C-0225", rules: []string{
		"ensure-default-service-accounts-has-only-default-roles",
		"automount-default-service-account",
	}},
	{controlID: "C-0231", rules: []string{"ensure-https-loadbalancers-encrypted-with-tls-aws"}},
	{controlID: "C-0234", rules: []string{"ensure-external-secrets-storage-is-in-use"}},
	{controlID: "C-0262", rules: []string{"anonymous-access-enabled"}},
	{controlID: "C-0263", rules: []string{"ingress-no-tls"}},
	{controlID: "C-0275", rules: []string{"host-pid-privileges"}},
	{controlID: "C-0276", rules: []string{"host-ipc-privileges"}},
	{controlID: "C-0292", rules: []string{"detect-nginx-ingress-controller-eol"}},
	{controlID: "C-0295", rules: []string{"duplicate-env-var"}},
	{controlID: "C-0296", rules: []string{"mismatching-selector"}},
}

// psaBaselineRules is shared by the six baseline PSA controls, which differ in
// which CIS item they cite rather than in what they evaluate.
var psaBaselineRules = []string{
	"pod-security-admission-baseline-applied-1",
	"pod-security-admission-baseline-applied-2",
}

// retiredAPIVersions are API versions Kubernetes has removed. Some regolibrary
// fixtures are still written against them, and a VAP's matchConstraints name
// concrete versions rather than regolibrary's apiVersions: ["*"], so those
// fixtures reach one engine and not the other. That is the fixture being old,
// not the control disagreeing, so the objects are left in the input (a rule that
// correlates resources still sees them) and only left out of the comparison.
var retiredAPIVersions = map[string]string{
	"batch/v1beta1":          "CronJob v1beta1, removed in Kubernetes 1.25",
	"storage.k8s.io/v1beta1": "CSIStorageCapacity v1beta1, removed in Kubernetes 1.27",
}

// parityVerdict is a per-resource outcome, as one engine reported it. It is the
// scan status plus the case processRule expresses by omission: a resource the
// engine never reached a verdict on, because no match block enumerated it or
// because the CEL policy's matchConstraints excluded it.
type parityVerdict string

const parityNotEvaluated parityVerdict = "not evaluated"

// parityCase is one regolibrary rule test: the objects it feeds a rule, kept
// together because a rule that correlates resources (a ServiceAccount with its
// RoleBinding, say) reads the whole input at once. Cases are evaluated
// separately so objects from one cannot answer for another.
type parityCase struct {
	name    string
	objects []map[string]any
	// retired holds the IDs of objects on a removed API version, keyed to the
	// reason, so the comparison can leave them out.
	retired map[string]string
}

func TestRegoCELParity(t *testing.T) {
	settings := regoLibrarySettings(t)

	for _, control := range regoCELParityControls {
		t.Run(control.controlID, func(t *testing.T) {
			rules := loadParityRules(t, control.rules)
			cases := parityCases(t, control.rules)
			require.NotEmpty(t, cases, "no regolibrary rule tests vendored for %s", control.controlID)

			evaluated := 0
			var disagreements []string

			for _, testCase := range cases {
				t.Run(testCase.name, func(t *testing.T) {
					rego := regoVerdicts(t, control, rules, testCase, settings)
					cel := celVerdicts(t, control, rules, testCase, settings)
					evaluated += len(cel)

					diff := compareVerdicts(rego, cel, testCase.retired)
					disagreements = append(disagreements, prefixEach(testCase.name, diff)...)
					if control.divergence == "" && len(diff) > 0 {
						t.Errorf("%s: Rego and CEL disagree:\n%s", control.controlID, strings.Join(diff, "\n"))
					}
				})
			}

			if control.divergence != "" {
				resolved := "so the entry can go"
				if control.gap {
					resolved = "so the gap is closed and the entry can go"
				}
				require.NotEmpty(t, disagreements,
					"%s agreed with Rego on every fixture, %s. It was listed as diverging: %s",
					control.controlID, resolved, control.divergence)
				return
			}

			// A control whose CEL policy matched nothing in any vendored fixture
			// agrees with Rego for the emptiest of reasons. Not asked of the
			// diverging controls: the PSA ones diverge precisely because the two
			// sides do not share a subject kind, so there is nothing for the CEL
			// policy to match in a fixture written for the Rego rule.
			require.NotZero(t, evaluated,
				"%s: the CEL policy did not evaluate a single vendored resource, so this control is not actually covered",
				control.controlID)
		})
	}
}

// TestRegoCELParityTestdataIsReferenced keeps the vendored tree and the control
// table in step. An orphan rule directory means a refresh copied something the
// harness never runs, which reads like coverage that is not there.
func TestRegoCELParityTestdataIsReferenced(t *testing.T) {
	referenced := make(map[string]struct{})
	for _, control := range regoCELParityControls {
		for _, rule := range control.rules {
			referenced[rule] = struct{}{}
		}
	}

	entries, err := os.ReadDir(regoCELParityRulesDir)
	require.NoError(t, err)

	var orphans []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, ok := referenced[entry.Name()]; !ok {
			orphans = append(orphans, entry.Name())
		}
	}
	require.Empty(t, orphans, "vendored rules no control in regoCELParityControls runs (from regolibrary %s)", regoCELParityLibraryVersion)

	for rule := range referenced {
		_, err := os.Stat(filepath.Join(regoCELParityRulesDir, rule, "raw.rego"))
		require.NoError(t, err, "rule %q is named in regoCELParityControls but not vendored", rule)
	}
}

// regoVerdicts runs the control's Rego rules and folds them into one verdict per
// resource, the way processControl folds a multi-rule control: any rule failing
// a resource fails it for the control.
func regoVerdicts(t *testing.T, control regoCELControl, rules []reporthandling.PolicyRule, testCase parityCase, settings map[string][]string) map[string]parityVerdict {
	t.Helper()

	scanner := newParityScanner(t, testCase.objects, settings)
	asControl := reporthandling.Control{ControlID: control.controlID, Rules: rules}

	verdicts := make(map[string]parityVerdict)
	for i := range rules {
		results, err := scanner.processRule(context.Background(), &rules[i], nil, evaluationScope{}, &asControl)
		require.NoError(t, err, "control %s, rule %s", control.controlID, rules[i].Name)
		mergeVerdicts(verdicts, results)
	}
	return verdicts
}

// celVerdicts runs the control's CEL policy over the same objects. The synthetic
// rule carries every match block the Rego rules carry, so both engines are
// offered the same candidates; whatever the policy's own matchConstraints then
// exclude shows up as a resource CEL never reached a verdict on, which is a
// disagreement worth seeing rather than one to hide.
//
// settings only keeps this scanner identical to the Rego one. Nothing on the CEL
// path reads postureControlInputs: the policy takes the params the bundle ships.
func celVerdicts(t *testing.T, control regoCELControl, rules []reporthandling.PolicyRule, testCase parityCase, settings map[string][]string) map[string]parityVerdict {
	t.Helper()

	celRule := reporthandling.PolicyRule{RuleLanguage: reporthandling.CELLanguage}
	celRule.Name = "cel-" + control.controlID
	for i := range rules {
		celRule.Match = append(celRule.Match, rules[i].Match...)
		celRule.DynamicMatch = append(celRule.DynamicMatch, rules[i].DynamicMatch...)
	}

	scanner := newParityScanner(t, testCase.objects, settings)
	asControl := reporthandling.Control{ControlID: control.controlID, Rules: []reporthandling.PolicyRule{celRule}}

	// An error here is almost always the bundle: a control the policies do not
	// carry, or one loadVAP refuses because the offline engine cannot honor it.
	results, err := scanner.processRule(context.Background(), &celRule, nil, evaluationScope{}, &asControl)
	require.NoError(t, err, "control %s", control.controlID)

	verdicts := make(map[string]parityVerdict)
	mergeVerdicts(verdicts, results)
	return verdicts
}

// mergeVerdicts folds one rule's results into the control's, using the same
// precedence the report does: a failure outranks an unknown verdict, which
// outranks a pass.
func mergeVerdicts(into map[string]parityVerdict, results map[string]*resourcesresults.ResourceAssociatedRule) {
	for resourceID, result := range results {
		if result == nil {
			continue
		}
		status := result.Status
		if existing, ok := into[resourceID]; ok {
			status = apis.Compare(apis.ScanningStatus(existing), status)
		}
		into[resourceID] = parityVerdict(status)
	}
}

// compareVerdicts returns one line per resource the two engines disagree on,
// skipping the ones on a removed API version.
func compareVerdicts(rego, cel map[string]parityVerdict, retired map[string]string) []string {
	resourceIDs := make([]string, 0, len(rego)+len(cel))
	seen := make(map[string]struct{}, len(rego)+len(cel))
	for _, side := range []map[string]parityVerdict{rego, cel} {
		for resourceID := range side {
			if _, ok := seen[resourceID]; ok {
				continue
			}
			seen[resourceID] = struct{}{}
			resourceIDs = append(resourceIDs, resourceID)
		}
	}
	sort.Strings(resourceIDs)

	var diff []string
	for _, resourceID := range resourceIDs {
		if _, skip := retired[resourceID]; skip {
			continue
		}
		regoVerdict, celVerdict := verdictOr(rego, resourceID), verdictOr(cel, resourceID)
		if regoVerdict != celVerdict {
			diff = append(diff, fmt.Sprintf("  %s: rego=%s cel=%s", resourceID, regoVerdict, celVerdict))
		}
	}
	return diff
}

func verdictOr(verdicts map[string]parityVerdict, resourceID string) parityVerdict {
	if verdict, ok := verdicts[resourceID]; ok {
		return verdict
	}
	return parityNotEvaluated
}

func prefixEach(prefix string, lines []string) []string {
	prefixed := make([]string, 0, len(lines))
	for _, line := range lines {
		prefixed = append(prefixed, prefix+line)
	}
	return prefixed
}

// newParityScanner builds a scanner over one case's objects. Each side gets its
// own, because processRuleOnScope writes aggregator output back into
// AllResources and neither run should see what the other added.
func newParityScanner(t *testing.T, objects []map[string]any, settings map[string][]string) *OPAProcessor {
	t.Helper()

	sessionObj := cautils.NewOPASessionObjMock()
	sessionObj.K8SResources = make(cautils.K8SResources)
	// NewOPAProcessor copies the session's RegoInputData over whatever the
	// dependencies argument carries, so the settings have to go in here.
	sessionObj.RegoInputData.PostureControlInputs = settings

	for _, object := range objects {
		workload := workloadinterface.NewWorkloadObj(object)
		require.NotNil(t, workload, "fixture is not a Kubernetes object: %v", object)
		sessionObj.AllResources[workload.GetID()] = workload

		key := resourceGroupKey(t, object)
		sessionObj.K8SResources[key] = append(sessionObj.K8SResources[key], workload.GetID())
	}
	for key := range sessionObj.K8SResources {
		sort.Strings(sessionObj.K8SResources[key])
	}

	return NewOPAProcessor(sessionObj, &resources.RegoDependenciesData{}, "test", "", "", false, nil)
}

// resourceGroupKey spells the collection key a fixture would have been collected
// under. The last segment is the kind rather than the plural resource name,
// which getKubernetesObjects accepts, so the harness needs no plural table of
// its own to cover the twenty-odd kinds these fixtures span.
func resourceGroupKey(t *testing.T, object map[string]any) string {
	t.Helper()

	apiVersion, _ := object["apiVersion"].(string)
	kind, _ := object["kind"].(string)
	require.NotEmpty(t, apiVersion, "fixture has no apiVersion")
	require.NotEmpty(t, kind, "fixture has no kind")

	group, version := "", apiVersion
	if slash := strings.Index(apiVersion, "/"); slash >= 0 {
		group, version = apiVersion[:slash], apiVersion[slash+1:]
	}
	return strings.Join([]string{group, version, kind}, "/")
}

// loadParityRules assembles the PolicyRule regolibrary's own export builds:
// rule.metadata.json with raw.rego as the rule body and filter.rego, where there
// is one, as the resource enumerator.
func loadParityRules(t *testing.T, names []string) []reporthandling.PolicyRule {
	t.Helper()

	rules := make([]reporthandling.PolicyRule, 0, len(names))
	for _, name := range names {
		dir := filepath.Join(regoCELParityRulesDir, name)

		metadata, err := os.ReadFile(filepath.Join(dir, "rule.metadata.json"))
		require.NoError(t, err)
		var rule reporthandling.PolicyRule
		require.NoError(t, json.Unmarshal(metadata, &rule))
		require.Equal(t, name, rule.Name, "rule directory and rule name disagree")

		body, err := os.ReadFile(filepath.Join(dir, "raw.rego"))
		require.NoError(t, err)
		rule.Rule = string(body)

		enumerator, err := os.ReadFile(filepath.Join(dir, "filter.rego"))
		switch {
		case err == nil:
			rule.ResourceEnumerator = string(enumerator)
		case os.IsNotExist(err):
		default:
			require.NoError(t, err)
		}

		rules = append(rules, rule)
	}
	return rules
}

// parityCases collects the regolibrary rule tests for a control's rules. A case
// is either a directory of manifests (test/<case>/input/) or a single file
// (test/<case>/input.yaml), which is how regolibrary writes them.
func parityCases(t *testing.T, ruleNames []string) []parityCase {
	t.Helper()

	var cases []parityCase
	for _, ruleName := range ruleNames {
		testDir := filepath.Join(regoCELParityRulesDir, ruleName, "test")
		entries, err := os.ReadDir(testDir)
		if os.IsNotExist(err) {
			continue
		}
		require.NoError(t, err)

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			caseDir := filepath.Join(testDir, entry.Name())
			objects := readCaseObjects(t, caseDir)
			if len(objects) == 0 {
				continue
			}
			cases = append(cases, parityCase{
				name:    ruleName + "/" + entry.Name(),
				objects: objects,
				retired: retiredObjects(t, objects),
			})
		}
	}
	return cases
}

// retiredObjects picks out the fixtures written against an API version
// Kubernetes has removed, by the ID the scan would give them.
func retiredObjects(t *testing.T, objects []map[string]any) map[string]string {
	t.Helper()

	retired := make(map[string]string)
	for _, object := range objects {
		apiVersion, _ := object["apiVersion"].(string)
		reason, ok := retiredAPIVersions[apiVersion]
		if !ok {
			continue
		}
		workload := workloadinterface.NewWorkloadObj(object)
		require.NotNil(t, workload, "fixture is not a Kubernetes object: %v", object)
		retired[workload.GetID()] = reason
	}
	return retired
}

func readCaseObjects(t *testing.T, caseDir string) []map[string]any {
	t.Helper()

	inputDir := filepath.Join(caseDir, "input")
	if info, err := os.Stat(inputDir); err == nil && info.IsDir() {
		entries, err := os.ReadDir(inputDir)
		require.NoError(t, err)

		objects := make([]map[string]any, 0, len(entries))
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			objects = append(objects, readManifest(t, filepath.Join(inputDir, entry.Name())))
		}
		return objects
	}

	for _, name := range []string{"input.yaml", "input.json"} {
		path := filepath.Join(caseDir, name)
		if _, err := os.Stat(path); err == nil {
			return []map[string]any{readManifest(t, path)}
		}
	}
	return nil
}

func readManifest(t *testing.T, path string) map[string]any {
	t.Helper()

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	// sigs.k8s.io/yaml decodes a single document, and silently ignoring the rest
	// would quietly shrink a fixture. No vendored fixture is multi-document
	// today; one that arrives with a refresh should be split, or this needs a
	// document-splitting reader. A leading separator is just a document opener.
	body := strings.TrimPrefix(string(raw), "---\n")
	require.NotContains(t, body, "\n---", "%s is a multi-document manifest, which the harness does not read", path)

	object := make(map[string]any)
	require.NoError(t, yaml.Unmarshal(raw, &object), "%s", path)
	return object
}

// regoLibrarySettings reads the postureControlInputs regolibrary ships, which is
// what a scan hands the Rego side when nothing has been overridden. The CEL side
// is not configured from here: its policies take the params the bundle ships.
func regoLibrarySettings(t *testing.T) map[string][]string {
	t.Helper()

	raw, err := os.ReadFile(regoCELParityConfigPath)
	require.NoError(t, err)

	var configuration struct {
		Settings struct {
			PostureControlInputs map[string][]string `json:"postureControlInputs"`
		} `json:"settings"`
	}
	require.NoError(t, json.Unmarshal(raw, &configuration))
	require.NotEmpty(t, configuration.Settings.PostureControlInputs,
		"%s carries no postureControlInputs", regoCELParityConfigPath)

	return configuration.Settings.PostureControlInputs
}
