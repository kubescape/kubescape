package cel

import (
	"fmt"
	"sort"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
)

// Categories, matching the groups of cases below.
const (
	parityCatValidation = "validation"
	parityCatRuntime    = "cel-runtime"
	parityCatGate       = "matchConditions"
	parityCatFailure    = "failurePolicy"
	parityCatVariables  = "variables"
	parityCatMessages   = "messages"
	parityCatParams     = "params"
	parityCatRequest    = "request"
	parityCatStatic     = "static-typing"
	parityCatBudget     = "budget"
	parityCatDecode     = "typed-decoding"
)

// parityOption adjusts a case built by parityNew.
type parityOption func(*parityCase)

// parityNew builds a case over a Pod in namespace "default", the shape most
// cases need; options replace what differs.
func parityNew(id, category string, opts ...parityOption) parityCase {
	c := parityCase{
		ID:       category + "/" + id,
		Category: category,
		Object:   parityPod,
		Resource: "pods",
	}
	for _, opt := range opts {
		opt(&c)
	}
	return c
}

func parityExprs(exprs ...string) parityOption {
	return func(c *parityCase) {
		for _, e := range exprs {
			c.Validations = append(c.Validations, parityValidation{Expression: e})
		}
	}
}

func parityValidations(v ...parityValidation) parityOption {
	return func(c *parityCase) { c.Validations = append(c.Validations, v...) }
}

func parityFailure(p admissionregistrationv1.FailurePolicyType) parityOption {
	return func(c *parityCase) { c.FailurePolicy = parityFailPolicy(p) }
}

func parityGateExprs(exprs ...string) parityOption {
	return func(c *parityCase) { c.MatchConditions = append(c.MatchConditions, exprs...) }
}

func parityVars(v ...parityVariable) parityOption {
	return func(c *parityCase) { c.Variables = append(c.Variables, v...) }
}

func parityObjectOf(f func() map[string]any, resource string) parityOption {
	return func(c *parityCase) { c.Object, c.Resource = f, resource }
}

func parityWithNamespace() parityOption {
	return func(c *parityCase) { c.Namespace = parityNamespace }
}

func parityWithParams(f func() map[string]any) parityOption {
	return func(c *parityCase) { c.ParamKind, c.Params = true, f }
}

func parityMissingParams() parityOption {
	return func(c *parityCase) { c.ParamKind = true }
}

func parityBudget(n int64) parityOption { return func(c *parityCase) { c.Budget = n } }

func parityCancelled() parityOption { return func(c *parityCase) { c.Cancel = true } }

func parityInputs(in ...parityInput) parityOption { return func(c *parityCase) { c.Inputs = in } }

func parityNote(s string) parityOption { return func(c *parityCase) { c.Note = s } }

func parityRequestOf(op admission.Operation, sub string, info *user.DefaultInfo) parityOption {
	return func(c *parityCase) { c.Operation, c.SubResource, c.User = op, sub, info }
}

func parityOldObject(f func() map[string]any) parityOption {
	return func(c *parityCase) { c.OldObject = f }
}

// parityExprCases builds one case per expression, over the same options.
func parityExprCases(prefix, category string, exprs map[string]string, opts ...parityOption) []parityCase {
	names := make([]string, 0, len(exprs))
	for name := range exprs {
		names = append(names, name)
	}
	sort.Strings(names)
	cases := make([]parityCase, 0, len(names))
	for _, name := range names {
		all := append([]parityOption{parityExprs(exprs[name])}, opts...)
		cases = append(cases, parityNew(prefix+"/"+name, category, all...))
	}
	return cases
}

func parityPod() map[string]any {
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      "web",
			"namespace": "default",
			"labels":    map[string]any{"app": "web", "tier": "front"},
		},
		"spec": map[string]any{
			"hostNetwork": true,
			"containers": []any{
				map[string]any{
					"name":            "app",
					"image":           "nginx:1.25",
					"securityContext": map[string]any{"privileged": true},
				},
				map[string]any{"name": "sidecar", "image": "redis:7"},
			},
		},
	}
}

func parityNamespace() map[string]any {
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata": map[string]any{
			"name":   "default",
			"labels": map[string]any{"env": "prod"},
		},
	}
}

func parityConfigMap() map[string]any {
	return map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata":   map[string]any{"name": "settings", "namespace": "default"},
		"data":       map[string]any{"limit": "3", "mode": "strict"},
	}
}

func parityCustomResource() map[string]any {
	return map[string]any{
		"apiVersion": "example.dev/v1",
		"kind":       "Widget",
		"metadata":   map[string]any{"name": "w1", "namespace": "default"},
		"spec":       map[string]any{"replicas": int64(2), "tags": nil, "nested": map[string]any{}},
	}
}

func parityIntList(n int) string {
	items := make([]string, n)
	for i := range items {
		items[i] = fmt.Sprint(i + 1)
	}
	return "[" + strings.Join(items, ",") + "]"
}

// parityCostly is a boolean expression whose cost grows with n squared.
func parityCostly(n int) string {
	list := parityIntList(n)
	return fmt.Sprintf("%[1]s.map(x, %[1]s.map(y, x * y)).size() > 0", list)
}

const (
	parityFail   = admissionregistrationv1.Fail
	parityIgnore = admissionregistrationv1.Ignore
)

// A. Basic validation outcomes.
func parityValidationCases() []parityCase {
	return []parityCase{
		parityNew("true", parityCatValidation, parityExprs("true")),
		parityNew("false", parityCatValidation, parityExprs("false")),
		parityNew("all-pass", parityCatValidation, parityExprs("true", "object.kind == 'Pod'", "object.metadata.name == 'web'")),
		parityNew("one-deny", parityCatValidation, parityExprs("true", "false", "true")),
		parityNew("several-deny", parityCatValidation, parityExprs("false", "true", "false", "false")),
		parityNew("no-validations", parityCatValidation),
		parityNew("order-kept", parityCatValidation, parityExprs("true", "false", "true", "false", "true")),
		parityNew("non-bool-int", parityCatValidation, parityExprs("1")),
		parityNew("non-bool-string", parityCatValidation, parityExprs("'yes'")),
		parityNew("non-bool-null", parityCatValidation, parityExprs("null")),
		parityNew("non-bool-list", parityCatValidation, parityExprs("[true]")),
		parityNew("runtime-error", parityCatValidation, parityExprs("object.spec.missing.field == 1")),
		parityNew("mixed-pass-deny-error", parityCatValidation, parityExprs("true", "false", "object.spec.missing.field == 1")),
		parityNew("error-then-deny", parityCatValidation, parityExprs("object.spec.missing.field == 1", "false")),
		parityNew("error-then-pass", parityCatValidation, parityExprs("object.spec.missing.field == 1", "true")),
		parityNew("errors-only", parityCatValidation, parityExprs("1 / 0 == 1", "object.spec.containers[9].name == 'x'")),
		parityNew("deny-on-label", parityCatValidation, parityExprs("object.metadata.labels['app'] == 'api'")),
		parityNew("pass-on-label", parityCatValidation, parityExprs("object.metadata.labels['app'] == 'web'")),
		parityNew("config-map", parityCatValidation, parityObjectOf(parityConfigMap, "configmaps"), parityExprs("object.data['limit'] == '3'", "object.data.mode == 'lax'")),
		parityNew("custom-resource", parityCatValidation, parityObjectOf(parityCustomResource, "widgets"), parityExprs("object.spec.replicas == 2", "object.spec.replicas > 2")),
	}
}

// B. CEL runtime behavior.
func parityRuntimeCases() []parityCase {
	var cases []parityCase
	cases = append(cases, parityExprCases("expr", parityCatRuntime, map[string]string{
		"missing-map-key":         "object.metadata.labels['absent'] == 'x'",
		"missing-field":           "object.spec.absent == 1",
		"missing-nested-field":    "object.spec.absent.deeper == 1",
		"list-index-out-of-range": "object.spec.containers[5].name == 'x'",
		"list-negative-index":     "object.spec.containers[-1].name == 'x'",
		"list-first":              "object.spec.containers[0].name == 'app'",
		"divide-by-zero":          "1 / 0 == 1",
		"modulo-by-zero":          "1 % 0 == 1",
		"and-short-circuit":       "false && 1 / 0 == 1",
		"or-short-circuit":        "true || 1 / 0 == 1",
		"and-error-first":         "1 / 0 == 1 && false",
		"or-error-first":          "1 / 0 == 1 || true",
		"ternary-short-circuit":   "true ? true : 1 / 0 == 1",
		"has-present":             "has(object.spec.hostNetwork)",
		"has-absent":              "has(object.spec.hostPID)",
		"has-absent-parent":       "has(object.spec.absent.deeper)",
		"has-map-key":             "has(object.metadata.labels.app)",
		"has-map-key-absent":      "has(object.metadata.labels.absent)",
		"in-map":                  "'app' in object.metadata.labels",
		"in-list":                 "'app' in object.spec.containers.map(c, c.name)",
		"all":                     "object.spec.containers.all(c, c.image.contains(':'))",
		"all-false":               "object.spec.containers.all(c, c.image.startsWith('nginx'))",
		"exists":                  "object.spec.containers.exists(c, c.name == 'sidecar')",
		"exists-one":              "object.spec.containers.exists_one(c, has(c.securityContext))",
		"exists-on-missing":       "object.spec.containers.exists(c, c.securityContext.privileged)",
		"filter-map":              "object.spec.containers.filter(c, has(c.securityContext)).map(c, c.name) == ['app']",
		"size":                    "object.spec.containers.size() == 2",
		"string-size":             "object.metadata.name.size() == 3",
		"int-conversion":          "int('42') == 42",
		"double-conversion":       "double('1.5') > 1.0",
		"string-conversion":       "string(42) == '42'",
		"bool-from-string":        "bool('true')",
		"string-functions":        "object.metadata.name.upperAscii() == 'WEB' && object.metadata.name.startsWith('w') && object.metadata.name.endsWith('b')",
		"string-matches":          "object.metadata.name.matches('^w.b$')",
		"string-split-join":       "'a,b,c'.split(',').join('-') == 'a-b-c'",
		"string-replace":          "'aaa'.replace('a', 'b') == 'bbb'",
		"string-substring":        "'hello'.substring(1, 3) == 'el'",
		"string-substring-range":  "'hello'.substring(3, 99) == 'lo'",
		"string-index-of":         "'hello'.indexOf('l') == 2",
		"list-concat":             "([1, 2] + [3]).size() == 3",
		"list-index-in-map":       "{'a': [1, 2]}['a'][1] == 2",
		"list-sort":               "[3, 1, 2].sort() == [1, 2, 3]",
		"list-slice":              "[1, 2, 3, 4].slice(1, 3) == [2, 3]",
		"list-sum":                "[1, 2, 3].sum() == 6",
		"list-min-max":            "[1, 5, 3].max() == 5 && [4, 2].min() == 2",
		"list-flatten":            "[[1], [2, 3]].flatten().size() == 3",
		"list-distinct":           "[1, 1, 2].distinct().size() == 2",
		"list-is-sorted":          "[1, 2, 3].isSorted()",
		"list-lists-set":          "sets.contains([1, 2, 3], [2, 3]) && sets.intersects([1, 2], [2, 3]) && sets.equivalent([1, 2], [2, 1])",
		"map-keys":                "object.metadata.labels.all(k, k.size() > 0)",
		"int-overflow":            "9223372036854775807 + 1 > 0",
		"uint-underflow":          "0u - 1u > 0u",
		"double-compare":          "1.5 < 2",
		"timestamp-parse":         "timestamp('2024-01-01T00:00:00Z') < timestamp('2025-01-01T00:00:00Z')",
		"duration":                "duration('1h') > duration('30m')",
		"bytes":                   "bytes('abc').size() == 3",
		"optional-or-value":       "object.?spec.?absent.orValue(1) == 1",
		"optional-present":        "object.?spec.?hostNetwork.orValue(false)",
		"optional-has-value":      "optional.of(1).hasValue() && !optional.none().hasValue()",
		"optional-value-of-none":  "optional.none().value() == 1",
		"optional-chain-or":       "optional.of(1).or(optional.of(2)).value() == 1",
		"optional-map-index":      "object.metadata.labels[?'absent'].orValue('d') == 'd'",
		"lists-range":             "lists.range(3) == [0, 1, 2]",
		"strings-quote":           "strings.quote('a') == '\"a\"'",
		"two-var-comprehension":   "[1, 2].all(i, v, i < v)",
		"transform-list":          "[1, 2].transformList(i, v, v * 2) == [2, 4]",
		"json-field-select":       "object.spec.containers[0].securityContext.privileged == true",
	})...)

	cases = append(cases, parityExprCases("library", parityCatRuntime, map[string]string{
		"quantity-compare":       "quantity('1Gi').isGreaterThan(quantity('1G'))",
		"quantity-add":           "quantity('1Gi').add(quantity('1Gi')).isGreaterThan(quantity('1Gi'))",
		"quantity-as-integer":    "quantity('2').asInteger() == 2",
		"quantity-invalid":       "quantity('lots')",
		"is-quantity":            "isQuantity('1Gi') && !isQuantity('x')",
		"ip-valid":               "isIP('10.0.0.1') && !isIP('10.0.0')",
		"ip-family":              "ip('10.0.0.1').family() == 4",
		"ip-canonical":           "ip('2001:db8::1').isGlobalUnicast()",
		"ip-loopback":            "ip('127.0.0.1').isLoopback()",
		"ip-invalid":             "ip('10.0.0')",
		"cidr-contains-ip":       "cidr('10.0.0.0/8').containsIP('10.1.1.1')",
		"cidr-contains-cidr":     "cidr('10.0.0.0/8').containsCIDR('10.1.0.0/16')",
		"cidr-masked":            "cidr('10.1.2.3/8').masked() == cidr('10.0.0.0/8')",
		"cidr-prefix-length":     "cidr('10.0.0.0/8').prefixLength() == 8",
		"cidr-invalid":           "cidr('10.0.0.0/99')",
		"url-parts":              "url('https://example.com:8080/a?b=c').getHostname() == 'example.com' && url('https://example.com:8080/a').getPort() == '8080'",
		"url-scheme":             "url('https://example.com').getScheme() == 'https'",
		"url-query":              "url('https://example.com/?a=b').getQuery()['a'] == ['b']",
		"url-invalid":            "url('::not a url::')",
		"is-url":                 "isURL('https://example.com') && !isURL('::')",
		"semver-compare":         "semver('1.2.3').isGreaterThan(semver('1.2.0'))",
		"semver-parts":           "semver('1.2.3').major() == 1 && semver('1.2.3').minor() == 2 && semver('1.2.3').patch() == 3",
		"semver-normalize":       "semver('v1.2', true).patch() == 0",
		"semver-invalid":         "semver('1.2')",
		"is-semver":              "isSemver('1.2.3') && !isSemver('1.2')",
		"format-dns1123-label":   "format.dns1123Label().validate('web') == optional.none()",
		"format-dns1123-invalid": "format.dns1123Label().validate('Web').hasValue()",
		"format-uri":             "format.uri().validate('https://example.com') == optional.none()",
		"format-named-missing":   "format.named('nope').hasValue()",
		"format-uuid":            "format.uuid().validate('123e4567-e89b-12d3-a456-426614174000') == optional.none()",
		"regex-find":             "'abc123'.find('[0-9]+') == '123'",
		"regex-find-all":         "'a1b2'.findAll('[0-9]').size() == 2",
		"authorizer":             "authorizer.group('').resource('pods').check('get').allowed()",
		"authorizer-request":     "authorizer.requestResource.check('get').allowed()",
	})...)
	return cases
}

// C. matchConditions and the gate.
func parityGateCases() []parityCase {
	costly := parityCostly(55)
	return []parityCase{
		parityNew("none", parityCatGate, parityExprs("false")),
		parityNew("one-true", parityCatGate, parityGateExprs("true"), parityExprs("false")),
		parityNew("one-false", parityCatGate, parityGateExprs("false"), parityExprs("false")),
		parityNew("all-true", parityCatGate, parityGateExprs("true", "object.kind == 'Pod'"), parityExprs("false")),
		parityNew("all-false", parityCatGate, parityGateExprs("false", "1 == 2"), parityExprs("false")),
		parityNew("true-then-false", parityCatGate, parityGateExprs("true", "false"), parityExprs("false")),
		parityNew("false-then-true", parityCatGate, parityGateExprs("false", "true"), parityExprs("false")),
		parityNew("reads-object", parityCatGate, parityGateExprs("object.metadata.labels['tier'] == 'front'"), parityExprs("false")),
		parityNew("reads-object-nonmatching", parityCatGate, parityGateExprs("object.metadata.labels['tier'] == 'back'"), parityExprs("false")),
		parityNew("skip-is-not-deny", parityCatGate, parityGateExprs("false"), parityExprs("false", "false")),
		parityNew("pass-after-gate", parityCatGate, parityGateExprs("true"), parityExprs("true")),
		parityNew("error-fail", parityCatGate, parityFailure(parityFail), parityGateExprs("1 / 0 == 1"), parityExprs("false")),
		parityNew("error-ignore", parityCatGate, parityFailure(parityIgnore), parityGateExprs("1 / 0 == 1"), parityExprs("false")),
		parityNew("error-default-policy", parityCatGate, parityGateExprs("1 / 0 == 1"), parityExprs("false")),
		parityNew("true-then-error-fail", parityCatGate, parityFailure(parityFail), parityGateExprs("true", "1 / 0 == 1"), parityExprs("false")),
		parityNew("true-then-error-ignore", parityCatGate, parityFailure(parityIgnore), parityGateExprs("true", "1 / 0 == 1"), parityExprs("false")),
		parityNew("error-then-false-fail", parityCatGate, parityFailure(parityFail), parityGateExprs("1 / 0 == 1", "false"), parityExprs("false")),
		parityNew("false-then-error-fail", parityCatGate, parityFailure(parityFail), parityGateExprs("false", "1 / 0 == 1"), parityExprs("false")),
		parityNew("error-then-false-ignore", parityCatGate, parityFailure(parityIgnore), parityGateExprs("1 / 0 == 1", "false"), parityExprs("false")),
		parityNew("false-then-error-ignore", parityCatGate, parityFailure(parityIgnore), parityGateExprs("false", "1 / 0 == 1"), parityExprs("false")),
		parityNew("missing-field-fail", parityCatGate, parityFailure(parityFail), parityGateExprs("object.spec.absent.field == 1"), parityExprs("false")),
		parityNew("non-bool-fail", parityCatGate, parityFailure(parityFail), parityGateExprs("1"), parityExprs("false")),
		parityNew("non-bool-ignore", parityCatGate, parityFailure(parityIgnore), parityGateExprs("1"), parityExprs("false")),
		parityNew("non-bool-then-false", parityCatGate, parityFailure(parityFail), parityGateExprs("'x'", "false"), parityExprs("false")),
		parityNew("namespace-object-is-null", parityCatGate, parityWithNamespace(), parityGateExprs("namespaceObject == null"), parityExprs("false"),
			parityNote("matchConditions bind namespaceObject to null even when the Namespace is known")),
		parityNew("namespace-object-read-fail", parityCatGate, parityWithNamespace(), parityFailure(parityFail), parityGateExprs("namespaceObject.metadata.name == 'default'"), parityExprs("false")),
		parityNew("namespace-object-read-ignore", parityCatGate, parityWithNamespace(), parityFailure(parityIgnore), parityGateExprs("namespaceObject.metadata.name == 'default'"), parityExprs("false")),
		parityNew("namespace-object-absent-labels", parityCatGate, parityFailure(parityFail), parityGateExprs("namespaceObject.metadata.labels.env == 'prod'"), parityExprs("false")),
		parityNew("variable-in-gate", parityCatGate, parityVars(parityVariable{"hostNet", "object.spec.hostNetwork == true"}), parityGateExprs("variables.hostNet"), parityExprs("false"),
			parityNote("a boolean variable expression: a bare dyn result does not compile upstream")),
		parityNew("variable-in-gate-false", parityCatGate, parityVars(parityVariable{"hostPID", "object.spec.hostPID == true"}), parityGateExprs("variables.hostPID"), parityExprs("false")),
		parityNew("variable-error-in-gate-fail", parityCatGate, parityFailure(parityFail), parityVars(parityVariable{"boom", "1 / 0 == 1"}), parityGateExprs("variables.boom"), parityExprs("false")),
		parityNew("params-in-gate", parityCatGate, parityWithParams(parityConfigMap), parityGateExprs("params.data.mode == 'strict'"), parityExprs("false")),
		parityNew("params-in-gate-nonmatching", parityCatGate, parityWithParams(parityConfigMap), parityGateExprs("params.data.mode == 'lax'"), parityExprs("false")),
		parityNew("params-missing-in-gate-fail", parityCatGate, parityMissingParams(), parityFailure(parityFail), parityGateExprs("params.data.mode == 'strict'"), parityExprs("false")),
		parityNew("gate-budget-exhausted-fail", parityCatBudget, parityFailure(parityFail), parityGateExprs(costly, costly, costly, costly, costly), parityExprs("false"),
			parityNote("five expensive conditions exceed the 2.5M match-condition budget together, though each fits alone")),
		parityNew("gate-budget-exhausted-ignore", parityCatBudget, parityFailure(parityIgnore), parityGateExprs(costly, costly, costly, costly, costly), parityExprs("false")),
		parityNew("gate-budget-false-first", parityCatBudget, parityFailure(parityFail), parityGateExprs("false", costly, costly, costly, costly, costly), parityExprs("false"),
			parityNote("a false condition does not stop the later ones from spending the budget")),
		parityNew("gate-within-budget", parityCatBudget, parityFailure(parityFail), parityGateExprs(costly, costly), parityExprs("false")),
		parityNew("gate-cancelled", parityCatBudget, parityCancelled(), parityGateExprs("true"), parityExprs("false")),
	}
}

// D. failurePolicy.
func parityFailurePolicyCases() []parityCase {
	var cases []parityCase
	for _, p := range []struct {
		name   string
		option parityOption
	}{
		{"fail", parityFailure(parityFail)},
		{"ignore", parityFailure(parityIgnore)},
		{"omitted", func(*parityCase) {}},
	} {
		cases = append(cases,
			parityNew("error/"+p.name, parityCatFailure, p.option, parityExprs("object.spec.absent.field == 1")),
			parityNew("error-and-pass/"+p.name, parityCatFailure, p.option, parityExprs("object.spec.absent.field == 1", "true")),
			parityNew("error-and-deny/"+p.name, parityCatFailure, p.option, parityExprs("object.spec.absent.field == 1", "false")),
			parityNew("deny-and-error/"+p.name, parityCatFailure, p.option, parityExprs("false", "object.spec.absent.field == 1")),
			parityNew("errors/"+p.name, parityCatFailure, p.option, parityExprs("1 / 0 == 1", "object.spec.absent.field == 1")),
			parityNew("non-bool/"+p.name, parityCatFailure, p.option, parityExprs("1")),
			parityNew("pass/"+p.name, parityCatFailure, p.option, parityExprs("true")),
			parityNew("deny/"+p.name, parityCatFailure, p.option, parityExprs("false")),
			parityNew("gate-error/"+p.name, parityCatFailure, p.option, parityGateExprs("1 / 0 == 1"), parityExprs("false")),
			parityNew("gate-false-and-error/"+p.name, parityCatFailure, p.option, parityGateExprs("1 / 0 == 1", "false"), parityExprs("false")),
			parityNew("variable-error/"+p.name, parityCatFailure, p.option, parityVars(parityVariable{"boom", "1 / 0 == 1"}), parityExprs("variables.boom")),
		)
	}
	return cases
}

// E. Variables.
//
// A variable that refers to itself (or two that refer to each other) is
// deliberately not a case: upstream rejects it at compile time, but the
// offline evaluator resolves variables lazily and recurses until the Go stack
// overflows, which is a fatal error that no test can record as an outcome.
func parityVariableCases() []parityCase {
	return []parityCase{
		parityNew("none", parityCatVariables, parityExprs("true")),
		parityNew("simple", parityCatVariables, parityVars(parityVariable{"hostNet", "object.spec.hostNetwork == true"}), parityExprs("variables.hostNet")),
		parityNew("simple-deny", parityCatVariables, parityVars(parityVariable{"hostNet", "object.spec.hostNetwork == true"}), parityExprs("!variables.hostNet")),
		parityNew("comparison", parityCatVariables, parityVars(parityVariable{"n", "object.spec.containers.size()"}), parityExprs("variables.n == 2", "variables.n == 3")),
		parityNew("chain", parityCatVariables, parityVars(parityVariable{"a", "1"}, parityVariable{"b", "variables.a + 1"}, parityVariable{"c", "variables.b * 3"}), parityExprs("variables.c == 6")),
		parityNew("used-by-several", parityCatVariables, parityVars(parityVariable{"names", "object.spec.containers.map(c, c.name)"}), parityExprs("'app' in variables.names", "'sidecar' in variables.names", "'ghost' in variables.names")),
		parityNew("several-variables", parityCatVariables, parityVars(parityVariable{"x", "1"}, parityVariable{"y", "2"}), parityExprs("variables.x < variables.y", "variables.x > variables.y")),
		parityNew("unused-ok", parityCatVariables, parityVars(parityVariable{"x", "1"}), parityExprs("true")),
		parityNew("unused-broken", parityCatVariables, parityVars(parityVariable{"boom", "1 / 0"}), parityExprs("true")),
		parityNew("used-broken-fail", parityCatVariables, parityFailure(parityFail), parityVars(parityVariable{"boom", "1 / 0 == 1"}), parityExprs("variables.boom == true", "true")),
		parityNew("used-broken-ignore", parityCatVariables, parityFailure(parityIgnore), parityVars(parityVariable{"boom", "1 / 0 == 1"}), parityExprs("variables.boom == true", "true")),
		parityNew("used-broken-only-one", parityCatVariables, parityVars(parityVariable{"boom", "1 / 0 == 1"}), parityExprs("true", "variables.boom == true", "false")),
		parityNew("broken-dependency", parityCatVariables, parityVars(parityVariable{"boom", "1 / 0"}, parityVariable{"dep", "variables.boom + 1"}), parityExprs("variables.dep == 1")),
		parityNew("missing-field", parityCatVariables, parityVars(parityVariable{"v", "object.spec.absent.field"}), parityExprs("variables.v == 1")),
		parityNew("memoized-reuse", parityCatVariables, parityVars(parityVariable{"n", "object.spec.containers.size()"}), parityExprs("variables.n == 2", "variables.n == 2", "variables.n == 2")),
		parityNew("references-params", parityCatVariables, parityWithParams(parityConfigMap), parityVars(parityVariable{"mode", "params.data.mode"}), parityExprs("variables.mode == 'strict'")),
		parityNew("references-namespace", parityCatVariables, parityWithNamespace(), parityVars(parityVariable{"env", "namespaceObject.metadata.labels.env"}), parityExprs("variables.env == 'prod'")),
		parityNew("references-request", parityCatVariables, parityVars(parityVariable{"op", "request.operation"}), parityExprs("variables.op == 'CREATE'")),
		parityNew("forward-reference", parityCatVariables, parityVars(parityVariable{"b", "variables.a + 1"}, parityVariable{"a", "1"}), parityExprs("variables.b == 2"),
			parityNote("upstream compiles variables in order, so a forward reference does not compile")),
		parityNew("undefined-variable", parityCatVariables, parityExprs("variables.nope == 1")),
		parityNew("bare-dyn-variable", parityCatVariables, parityVars(parityVariable{"hostNet", "object.spec.hostNetwork"}), parityExprs("variables.hostNet"),
			parityNote("a dyn-typed result is not a bool at compile time upstream")),
		parityNew("typed-variable-bool", parityCatVariables, parityVars(parityVariable{"hostNet", "object.spec.hostNetwork == true"}), parityExprs("variables.hostNet")),
		parityNew("variable-not-bool", parityCatVariables, parityVars(parityVariable{"n", "1"}), parityExprs("variables.n")),
	}
}

// F. Message behavior.
func parityMessageCases() []parityCase {
	long := strings.Repeat("x", 6000)
	msg := func(id string, v parityValidation, opts ...parityOption) parityCase {
		return parityNew(id, parityCatMessages, append([]parityOption{parityValidations(v)}, opts...)...)
	}
	return []parityCase{
		msg("static", parityValidation{Expression: "false", Message: "must not be false"}),
		msg("static-trimmed", parityValidation{Expression: "false", Message: "  padded  "}),
		msg("static-whitespace-only", parityValidation{Expression: "false", Message: "   "}),
		msg("default", parityValidation{Expression: "false"}),
		msg("default-trims-expression", parityValidation{Expression: "  false  "}),
		msg("expression", parityValidation{Expression: "false", Message: "static", MessageExpression: "'pod ' + object.metadata.name"}),
		msg("expression-no-static", parityValidation{Expression: "false", MessageExpression: "'pod ' + object.metadata.name"}),
		msg("expression-trimmed", parityValidation{Expression: "false", Message: "static", MessageExpression: "'  hi  '"}),
		msg("expression-error-static", parityValidation{Expression: "false", Message: "static", MessageExpression: "1 / 0 == 1 ? 'a' : 'b'"}),
		msg("expression-error-default", parityValidation{Expression: "false", MessageExpression: "1 / 0 == 1 ? 'a' : 'b'"}),
		msg("expression-missing-field", parityValidation{Expression: "false", Message: "static", MessageExpression: "object.spec.absent.field"}),
		msg("expression-non-string", parityValidation{Expression: "false", Message: "static", MessageExpression: "1"}),
		msg("expression-null", parityValidation{Expression: "false", Message: "static", MessageExpression: "null"}),
		msg("expression-empty", parityValidation{Expression: "false", Message: "static", MessageExpression: "''"}),
		msg("expression-whitespace", parityValidation{Expression: "false", Message: "static", MessageExpression: "'   '"}),
		msg("expression-multiline", parityValidation{Expression: "false", Message: "static", MessageExpression: "'a\\nb'"}),
		msg("expression-long", parityValidation{Expression: "false", Message: "static", MessageExpression: "'" + long + "'"}),
		msg("expression-on-pass", parityValidation{Expression: "true", Message: "static", MessageExpression: "1 / 0 == 1 ? 'a' : 'b'"}),
		msg("expression-on-error", parityValidation{Expression: "1 / 0 == 1", Message: "static", MessageExpression: "'dynamic'"}),
		msg("expression-reads-variable", parityValidation{Expression: "false", MessageExpression: "'count ' + string(variables.n)"},
			parityVars(parityVariable{"n", "object.spec.containers.size()"})),
		msg("expression-reads-params", parityValidation{Expression: "false", MessageExpression: "'mode ' + params.data.mode"}, parityWithParams(parityConfigMap)),
		msg("expression-reads-namespace", parityValidation{Expression: "false", MessageExpression: "'ns ' + namespaceObject.metadata.name"}, parityWithNamespace()),
		msg("expression-reads-request", parityValidation{Expression: "false", MessageExpression: "'op ' + request.operation"}),
		msg("expression-authorizer", parityValidation{Expression: "false", Message: "static", MessageExpression: "string(authorizer.group('').resource('pods').check('get').allowed())"}),
		parityNew("several-denials", parityCatMessages, parityValidations(
			parityValidation{Expression: "false", Message: "first"},
			parityValidation{Expression: "true", Message: "never shown"},
			parityValidation{Expression: "false", MessageExpression: "'second'"},
			parityValidation{Expression: "false"})),
		parityNew("error-carries-no-message", parityCatMessages, parityValidations(
			parityValidation{Expression: "1 / 0 == 1", Message: "static", MessageExpression: "'dynamic'"})),
	}
}

// G. Parameters.
func parityParamCases() []parityCase {
	configMap := func(data map[string]any) func() map[string]any {
		return func() map[string]any {
			return map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "settings"}, "data": data}
		}
	}
	return []parityCase{
		parityNew("no-param-kind", parityCatParams, parityExprs("true")),
		parityNew("valid", parityCatParams, parityWithParams(parityConfigMap), parityExprs("params.data.limit == '3'", "params.data.mode == 'strict'")),
		parityNew("valid-deny", parityCatParams, parityWithParams(parityConfigMap), parityExprs("params.data.limit == '9'")),
		parityNew("field-present", parityCatParams, parityWithParams(parityConfigMap), parityExprs("has(params.data.limit)")),
		parityNew("field-absent", parityCatParams, parityWithParams(parityConfigMap), parityExprs("has(params.data.absent)")),
		parityNew("field-absent-read-fail", parityCatParams, parityFailure(parityFail), parityWithParams(parityConfigMap), parityExprs("params.data.absent == 'x'")),
		parityNew("field-absent-read-ignore", parityCatParams, parityFailure(parityIgnore), parityWithParams(parityConfigMap), parityExprs("params.data.absent == 'x'")),
		parityNew("missing-object", parityCatParams, parityMissingParams(), parityExprs("params.data.limit == '3'")),
		parityNew("missing-object-is-null", parityCatParams, parityMissingParams(), parityExprs("params == null")),
		parityNew("missing-object-has", parityCatParams, parityMissingParams(), parityExprs("has(params.data)")),
		parityNew("wrong-shape-number-as-string", parityCatParams, parityWithParams(parityConfigMap), parityExprs("params.data.limit > 2")),
		parityNew("wrong-shape-object", parityCatParams, parityWithParams(configMap(map[string]any{"limit": map[string]any{"n": "3"}})), parityExprs("params.data.limit == '3'")),
		parityNew("empty-data", parityCatParams, parityWithParams(configMap(map[string]any{})), parityExprs("size(params.data) == 0", "has(params.data.limit)")),
		parityNew("null-data", parityCatParams, parityWithParams(configMap(nil)), parityExprs("has(params.data)")),
		parityNew("params-metadata", parityCatParams, parityWithParams(parityConfigMap), parityExprs("params.metadata.name == 'settings'", "params.kind == 'ConfigMap'", "params.apiVersion == 'v1'")),
		parityNew("params-in-variable", parityCatParams, parityWithParams(parityConfigMap), parityVars(parityVariable{"mode", "params.data.mode"}), parityExprs("variables.mode == 'strict'")),
		parityNew("params-in-message", parityCatParams, parityWithParams(parityConfigMap), parityValidations(parityValidation{Expression: "false", MessageExpression: "params.data.mode"})),
		parityNew("params-without-param-kind", parityCatParams, parityExprs("params.data.limit == '3'"),
			parityNote("a policy without paramKind does not declare params")),
		parityNew("params-null-without-param-kind", parityCatParams, parityExprs("params == null")),
	}
}

// H. Admission request and attribute shapes.
func parityRequestCases() []parityCase {
	var cases []parityCase
	cases = append(cases, parityExprCases("field", parityCatRequest, map[string]string{
		"operation":                  "request.operation == 'CREATE'",
		"name":                       "request.name == 'web'",
		"namespace":                  "request.namespace == 'default'",
		"kind":                       "request.kind.kind == 'Pod' && request.kind.version == 'v1' && request.kind.group == ''",
		"resource":                   "request.resource.resource == 'pods' && request.resource.version == 'v1' && request.resource.group == ''",
		"request-kind":               "request.requestKind.kind == 'Pod'",
		"request-resource":           "request.requestResource.resource == 'pods'",
		"sub-resource":               "request.subResource == ''",
		"has-sub-resource":           "has(request.subResource)",
		"request-sub-resource":       "request.requestSubResource == ''",
		"dry-run":                    "request.dryRun == false",
		"options-present":            "has(request.options)",
		"options-null":               "request.options == null",
		"uid":                        "request.uid == ''",
		"has-uid":                    "has(request.uid)",
		"has-object":                 "has(request.object)",
		"has-old-object":             "has(request.oldObject)",
		"old-object-null":            "oldObject == null",
		"object-matches-request":     "object.metadata.name == request.name",
		"user-name-empty":            "request.userInfo.username == ''",
		"has-user-name":              "has(request.userInfo.username)",
		"user-groups-size":           "request.userInfo.groups.size() == 0",
		"has-user-groups":            "has(request.userInfo.groups)",
		"user-uid":                   "request.userInfo.uid == ''",
		"has-user-uid":               "has(request.userInfo.uid)",
		"user-extra":                 "size(request.userInfo.extra) == 0",
		"has-user-extra":             "has(request.userInfo.extra)",
		"has-user-info":              "has(request.userInfo)",
		"unknown-field":              "has(request.noSuchField)",
		"unknown-field-read":         "request.noSuchField == 1",
		"namespace-object-null":      "namespaceObject == null",
		"authorizer-undeclared-here": "authorizer == null",
	})...)

	cases = append(cases, parityExprCases("namespace-object", parityCatRequest, map[string]string{
		"name":                  "namespaceObject.metadata.name == 'default'",
		"label":                 "namespaceObject.metadata.labels.env == 'prod'",
		"has-labels":            "has(namespaceObject.metadata.labels)",
		"has-annotations":       "has(namespaceObject.metadata.annotations)",
		"has-creation-time":     "has(namespaceObject.metadata.creationTimestamp)",
		"has-spec":              "has(namespaceObject.spec)",
		"has-status":            "has(namespaceObject.status)",
		"kind":                  "namespaceObject.kind == 'Namespace'",
		"api-version":           "namespaceObject.apiVersion == 'v1'",
		"has-kind":              "has(namespaceObject.kind)",
		"label-absent-key":      "namespaceObject.metadata.labels.absent == 'x'",
		"label-absent-key-safe": "!has(namespaceObject.metadata.labels.absent)",
	}, parityWithNamespace())...)

	updated := func() map[string]any {
		o := parityPod()
		o["metadata"].(map[string]any)["labels"].(map[string]any)["tier"] = "back"
		return o
	}
	cases = append(cases,
		parityNew("op/update-operation", parityCatRequest, parityRequestOf(admission.Update, "", nil), parityOldObject(updated), parityExprs("request.operation == 'UPDATE'"),
			parityNote("Kubescape models every resource as a fresh CREATE")),
		parityNew("op/update-old-object", parityCatRequest, parityRequestOf(admission.Update, "", nil), parityOldObject(updated), parityExprs("oldObject != null && oldObject.metadata.labels.tier == 'back'")),
		parityNew("op/create-without-old-object", parityCatRequest, parityExprs("oldObject == null")),
		parityNew("op/sub-resource", parityCatRequest, parityRequestOf(admission.Update, "status", nil), parityOldObject(updated), parityExprs("request.subResource == 'status'"),
			parityNote("the scan does not evaluate subresources")),
		parityNew("user/identity", parityCatRequest, parityRequestOf(admission.Create, "", &user.DefaultInfo{Name: "alice", UID: "u-1", Groups: []string{"dev", "system:authenticated"}}),
			parityExprs("request.userInfo.username == 'alice'"), parityNote("the scan has no requesting identity")),
		parityNew("user/groups", parityCatRequest, parityRequestOf(admission.Create, "", &user.DefaultInfo{Name: "alice", Groups: []string{"dev"}}),
			parityExprs("'dev' in request.userInfo.groups")),
		parityNew("user/extra", parityCatRequest, parityRequestOf(admission.Create, "", &user.DefaultInfo{Name: "alice", Extra: map[string][]string{"team": {"red"}}}),
			parityExprs("request.userInfo.extra['team'] == ['red']")),
		parityNew("cluster-scoped/namespace-object", parityCatRequest, parityObjectOf(parityNamespace, "namespaces"), parityExprs("request.namespace == ''", "request.name == 'default'", "namespaceObject == null")),
		parityNew("cluster-scoped/kind", parityCatRequest, parityObjectOf(parityNamespace, "namespaces"), parityExprs("request.kind.kind == 'Namespace'", "request.resource.resource == 'namespaces'")),
		parityNew("grouped-resource", parityCatRequest, parityObjectOf(parityDeployment, "deployments"), parityExprs("request.resource.group == 'apps'", "request.resource.resource == 'deployments'", "request.kind.group == 'apps'")),
		parityNew("custom-resource", parityCatRequest, parityObjectOf(parityCustomResource, "widgets"), parityExprs("request.resource.group == 'example.dev'", "request.resource.resource == 'widgets'")),
	)
	return cases
}

func parityDeployment() map[string]any {
	return map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "api", "namespace": "default"},
		"spec": map[string]any{
			"replicas": int64(3),
			"selector": map[string]any{"matchLabels": map[string]any{"app": "api"}},
			"template": map[string]any{
				"metadata": map[string]any{"labels": map[string]any{"app": "api"}},
				"spec":     map[string]any{"containers": []any{map[string]any{"name": "api", "image": "api:1"}}},
			},
		},
	}
}

// J. Static typing and compilation.
func parityStaticTypingCases() []parityCase {
	return parityExprCases("expr", parityCatStatic, map[string]string{
		"bare-dyn-field":          "object.spec.hostNetwork",
		"bare-dyn-index":          "object.metadata.labels['app']",
		"non-bool-literal":        "1",
		"non-bool-string":         "'x'",
		"incompatible-operands":   "1 + 'a' == 1",
		"incompatible-comparison": "object.spec.containers == 1",
		"unknown-identifier":      "nope == 1",
		"unknown-function":        "nope() == 1",
		"unknown-method":          "object.kind.noSuchMethod()",
		"wrong-arity":             "size() == 1",
		"wrong-argument-type":     "size(1) == 1",
		"syntax-error":            "object.kind ==",
		"unbalanced":              "(true",
		"empty":                   "",
		"regex-literal-invalid":   "'a'.matches('[')",
		"int-literal-overflow":    "9223372036854775808 > 0",
		"reserved-word":           "if == 1",
		"undeclared-request-uid":  "request.uid == ''",
		"undeclared-request-body": "request.object != null",
		"authorizer-compiles":     "authorizer.group('').resource('pods').check('get').allowed() || true",
		"not-operator-on-string":  "!'x'",
		"in-on-non-container":     "1 in 2",
		"ternary-mismatch":        "true ? 1 : 'a'",
		"optional-on-non-opt":     "object.metadata.name.orValue('x') == 'x'",
	}, parityNote("compile-time behavior: the apiserver refuses such a policy when it is created"))
}

// K. Cost budget and cancellation, beyond the gate budget cases above.
func parityBudgetCases() []parityCase {
	costly := parityCostly(55)
	return []parityCase{
		parityNew("validation-within-budget", parityCatBudget, parityExprs("true", "false", "true")),
		parityNew("validation-exhausts-first", parityCatBudget, parityBudget(1), parityExprs(costly, "false")),
		parityNew("validation-exhausts-second", parityCatBudget, parityBudget(400), parityExprs("false", costly, "false"),
			parityNote("the first denial is reached before the budget runs out")),
		parityNew("validation-exhausts-last", parityCatBudget, parityBudget(400), parityExprs("true", "true", costly)),
		parityNew("validation-exhausts-ignore", parityCatBudget, parityFailure(parityIgnore), parityBudget(400), parityExprs("false", costly, "false")),
		parityNew("validation-exhausts-fail", parityCatBudget, parityFailure(parityFail), parityBudget(400), parityExprs("false", costly, "false")),
		parityNew("budget-shared-across-validations", parityCatBudget, parityBudget(4000), parityExprs(costly, costly, costly, "false")),
		parityNew("variable-exhausts-budget", parityCatBudget, parityBudget(400), parityVars(parityVariable{"big", costly}), parityExprs("variables.big", "true")),
		parityNew("variable-within-budget", parityCatBudget, parityVars(parityVariable{"big", costly}), parityExprs("variables.big", "variables.big")),
		parityNew("message-exhausts-budget", parityCatBudget, parityBudget(400),
			parityValidations(parityValidation{Expression: "false", Message: "static", MessageExpression: costly + " ? 'a' : 'b'"})),
		parityNew("message-within-budget", parityCatBudget,
			parityValidations(parityValidation{Expression: "false", Message: "static", MessageExpression: costly + " ? 'a' : 'b'"})),
		parityNew("cancelled-trivial", parityCatBudget, parityCancelled(), parityExprs("true", "false")),
		parityNew("cancelled-comprehension", parityCatBudget, parityCancelled(), parityExprs(parityCostly(300))),
	}
}
