package fixhandler

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	storagev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestYAMLTreeEditor_ScalarSourcePreservation(t *testing.T) {
	input := "# unchanged\nspec:\n  privileged:   true    # keep this spacing\n  image: 'nginx:old'\n"
	want := "# unchanged\nspec:\n  privileged:   false    # keep this spacing\n  image: 'nginx:old'\n"
	got, err := ApplyFixToContent(context.Background(), input, FixPathToValidYamlExpression("spec.privileged", "false", 0))
	require.NoError(t, err)
	require.Equal(t, want, got)
	var parsed map[string]any
	require.NoError(t, yaml.Unmarshal([]byte(got), &parsed))
	require.Equal(t, false, parsed["spec"].(map[string]any)["privileged"])
}

func checkYAMLEdit(t *testing.T, input, expression, want string) string {
	t.Helper()
	got, err := ApplyFixToContent(context.Background(), input, expression)
	require.NoError(t, err)
	require.Equal(t, want, got)
	docs, err := decodeDocumentRoots(got)
	require.NoError(t, err)
	for _, doc := range docs {
		var value any
		require.NoError(t, doc.Decode(&value))
	}
	return got
}

func TestYAMLTreeEditor_ScalarTypesAndTokens(t *testing.T) {
	tests := []struct {
		name, input, value, want string
		semantic                 any
	}{
		{"single quotes", "target: 'it''s old'   # note\n", "it's new", "target: 'it''s new'   # note\n", "it's new"},
		{"escaped double quotes", "target: \"old\\\"quoted\\\\value\" # note\n", "new\"quoted\\value", "target: \"new\\\"quoted\\\\value\" # note\n", "new\"quoted\\value"},
		{"unicode", "{前: 雪, target:   \"古い\", 後: 🌳}\n", "新しい", "{前: 雪, target:   \"新しい\", 後: 🌳}\n", "新しい"},
		{"typed boolean", "target: 'true'\n", "false", "target: false\n", false},
		{"number", "target:  1 # replicas\n", "2", "target:  2 # replicas\n", 2},
		{"literal null", "target: old\n", "null", "target: \"null\"\n", "null"},
		{"literal expression", "target: old\n", `a | strenv(SECRET)`, "target: a | strenv(SECRET)\n", `a | strenv(SECRET)`},
		{"literal syntax", "target: old\n", "a: b # c", "target: 'a: b # c'\n", "a: b # c"},
		{"literal backslash", "target: old\n", `C:\new\path`, "target: C:\\new\\path\n", `C:\new\path`},
		{"newline string", "target: old\n", "first\nsecond", "target: \"first\\nsecond\"\n", "first\nsecond"},
		{"empty string", "target: old\n", "", "target: \"\"\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr := FixPathToValidYamlExpression("target", tt.value, 0)
			got := checkYAMLEdit(t, tt.input, expr, tt.want)
			var value map[string]any
			require.NoError(t, yaml.Unmarshal([]byte(got), &value))
			require.Equal(t, tt.semantic, value["target"])
			checkYAMLEdit(t, got, expr, got)
		})
	}
}

func TestYAMLTreeEditor_CollectionsAndPaths(t *testing.T) {
	tests := []struct{ name, input, expression, want string }{
		{"nested insertion", "spec:\n  containers:\n  - name: app\n", `select(di==0).spec.containers[0].securityContext.capabilities.drop |= ["ALL"]`, "spec:\n  containers:\n  - name: app\n    securityContext:\n      capabilities:\n        drop:\n          - ALL\n"},
		{"mapping append", "containers:\n- name: app\n  image: old\n", `select(di==0).containers += {"name": "other", "image": "new"}`, "containers:\n- name: app\n  image: old\n- name: other\n  image: new\n"},
		{"sequence append", "args: [--foo] # keep\n", `select(di==0).args += ["--bar"]`, "args: [--foo, --bar] # keep\n"},
		{"hash in flow scalar", "args: [--foo=#yes]\n", `select(di==0).args += ["next"]`, "args: [--foo=#yes, next]\n"},
		{"apostrophe in flow scalar", "args: [can't]\n", `select(di==0).args += ["next"]`, "args: [can't, next]\n"},
		{"trailing comma", "args: [one,]\n", `select(di==0).args += ["next"]`, "args: [one, next]\n"},
		{"next index", "args: [--foo]\n", `select(di==0).args[1] |= "--bar"`, "args: [--foo, --bar]\n"},
		{"element replacement", "args: [  'old', keep ]\n", `select(di==0).args[0] |= "new"`, "args: [  'new', keep ]\n"},
		{"flow replacement", "args: [old, keep]  # note\n", `select(di==0).args |= ["new", "next"]`, "args: [new, next]  # note\n"},
		{"block replacement", "args:\n- old\n- keep\nafter: unchanged\n", `select(di==0).args |= ["new", "next"]`, "args:\n- new\n- next\nafter: unchanged\n"},
		{"indentless empty replacement", "args:\n- old\nafter: unchanged\n", `select(di==0).args |= []`, "args:\n  []\nafter: unchanged\n"},
		{"indentless mapping replacement", "args:\n- old\nafter: unchanged\n", `select(di==0).args |= {"x": true, "y": false}`, "args:\n  x: true\n  y: false\nafter: unchanged\n"},
		{"indentless scalar replacement", "args:\n- old\nafter: unchanged\n", `select(di==0).args |= false`, "args:\n  false\nafter: unchanged\n"},
		{"flow mapping insertion", "spec: {old: true} # note\n", `select(di==0).spec.new |= false`, "spec: {old: true, new: false} # note\n"},
		{"empty mapping insertion", "spec: {} # note\n", `select(di==0).spec.new |= false`, "spec: {new: false} # note\n"},
		{"empty sequence insertion", "args: [] # note\n", `select(di==0).args[0] |= "new"`, "args: [new] # note\n"},
		{"wildcard", "items:\n- target: true # one\n- target: true # two\n", `select(di==0).items[*].target |= false`, "items:\n- target: false # one\n- target: false # two\n"},
		{"quoted keys", "metadata:\n  annotations:\n    example.org/key.name: old\n", `select(di==0).metadata.annotations."example.org/key.name" |= "new"`, "metadata:\n  annotations:\n    example.org/key.name: new\n"},
		{"delete mapping", "spec:\n  keep: true\n  remove: false\nafter: unchanged\n", `del(select(di==0).spec.remove)`, "spec:\n  keep: true\nafter: unchanged\n"},
		{"delete mapping first key in sequence", "items:\n  - name: a\n    # keep value comment\n    value: 1\n", `del(select(di==0).items[0].name)`, "items:\n    # keep value comment\n  - value: 1\n"},
		{"null mapping", "spec:\n", `select(di==0).spec.enabled |= false`, "spec: {enabled: false}\n"},
		{"null sequence", "args:\n", `select(di==0).args[0] |= "new"`, "args: [new]\n"},
		{"delete flow element", "args: [one, two, three]\n", `del(select(di==0).args[1])`, "args: [one, three]\n"},
		{"delete final flow element", "args: [one, two]\n", `del(select(di==0).args[1])`, "args: [one]\n"},
		{"delete single block element", "args:\n- one\n", `del(select(di==0).args[0])`, "args: []\n"},
		{"delete with quoted key", "\"args\":\n- one\n", `del(select(di==0).args[0])`, "\"args\":\n  []\n"},
		{"delete with key comment", "args: # note\n- one\n", `del(select(di==0).args[0])`, "args: # note\n  []\n"},
		{"insert after multiline plain", "spec:\n  message: this\n    continues\nafter: unchanged\n", `select(di==0).spec.new |= false`, "spec:\n  message: this\n    continues\n  new: false\nafter: unchanged\n"},
		{"insert after block scalar", "spec:\n  message: |\n    this\n    continues\nafter: unchanged\n", `select(di==0).spec.new |= false`, "spec:\n  message: |\n    this\n    continues\n  new: false\nafter: unchanged\n"},
		{"insert after anchored quoted scalar", "spec:\n  text: &v \"hello\"\n", `select(di==0).spec.new |= false`, "spec:\n  text: &v \"hello\"\n  new: false\n"},
		{"insert after anchored empty collection", "spec:\n  text: &v []\n", `select(di==0).spec.new |= false`, "spec:\n  text: &v []\n  new: false\n"},
		{"four spaces", "spec:\n    nested:\n        old: true\n", `select(di==0).spec.nested.new.deep |= false`, "spec:\n    nested:\n        old: true\n        new:\n            deep: false\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { checkYAMLEdit(t, tt.input, tt.expression, tt.want) })
	}
}

func TestYAMLTreeEditor_CollectionStringValues(t *testing.T) {
	tests := []struct {
		expression, want string
		value            any
	}{
		{`select(di==0).args += ["C:\new"]`, "args: ['C:\\new']\n", []any{`C:\new`}},
		{`select(di==0).args |= ["C:\new"]`, "args: ['C:\\new']\n", []any{`C:\new`}},
		{`select(di==0).args += {"path": "C:\new", "nested": ["say \"hi\""]}`, "args: [{path: 'C:\\new', nested: [say \"hi\"]}]\n", []any{map[string]any{"path": `C:\new`, "nested": []any{`say "hi"`}}}},
		{"select(di==0).args += [\"first\nsecond\"]", "args: [\"first\\nsecond\"]\n", []any{"first\nsecond"}},
	}
	for _, tt := range tests {
		t.Run(tt.expression, func(t *testing.T) {
			got := checkYAMLEdit(t, "args: []\n", tt.expression, tt.want)
			var obj map[string]any
			require.NoError(t, yaml.Unmarshal([]byte(got), &obj))
			require.Equal(t, tt.value, obj["args"])
		})
	}
}

func TestYAMLTreeEditor_FlowScalarDelimiters(t *testing.T) {
	for _, value := range []string{"a,b", "a]b", "a}b", "a: b", "[one]"} {
		t.Run(value, func(t *testing.T) {
			got := checkYAMLEdit(t, "args: [old]\n", FixPathToValidYamlExpression("args[0]", value, 0), "args: ['"+value+"']\n")
			var obj map[string]any
			require.NoError(t, yaml.Unmarshal([]byte(got), &obj))
			require.Equal(t, []any{value}, obj["args"])
			got = checkYAMLEdit(t, "spec: {target: old}\n", FixPathToValidYamlExpression("spec.target", value, 0), "spec: {target: '"+value+"'}\n")
			require.NoError(t, yaml.Unmarshal([]byte(got), &obj))
			require.Equal(t, map[string]any{"target": value}, obj["spec"])
		})
	}
}

func TestYAMLTreeEditor_DeterministicPipeline(t *testing.T) {
	input := "spec:\n  old: true\n"
	expr := `select(di==0).spec.nested.a |= true | select(di==0).spec.nested.b |= false | select(di==0).spec.old |= false | select(di==0).spec.old |= true`
	want := "spec:\n  old: true\n  nested:\n    a: true\n    b: false\n"
	got := checkYAMLEdit(t, input, expr, want)
	checkYAMLEdit(t, got, expr, want)
	// Preserve explicit sequence semantics: delete changes subsequent indices.
	checkYAMLEdit(t, "args: [one, two]\n", `del(select(di==0).args[0]) | select(di==0).args += ["three"] | select(di==0).args[0] |= "new"`, "args: [new, three]\n")
	checkYAMLEdit(t, "spec: {old: true}\n", `select(di==0).spec |= {"child": true} | select(di==0).spec.child |= false`, "spec: {child: false}\n")
}

func TestYAMLTreeEditor_DocumentsAndNewlines(t *testing.T) {
	for _, nl := range []string{"\n", "\r\n"} {
		for _, final := range []bool{true, false} {
			t.Run(fmt.Sprintf("newline=%q/final=%v", nl, final), func(t *testing.T) {
				input := "# leading comment\n---\n---\napiVersion: v1\nkind: Pod\nmetadata: {name: first}\nspec: {hostNetwork: true}\n---\n# empty\n---\napiVersion: v1\nkind: Pod\nmetadata: {name: second}\nspec: {hostNetwork: true}\n---\n"
				if !final {
					input = strings.TrimSuffix(input, "\n")
				}
				input = strings.ReplaceAll(input, "\n", nl)
				want := strings.Replace(input, "metadata: {name: second}"+nl+"spec: {hostNetwork: true}", "metadata: {name: second}"+nl+"spec: {hostNetwork: false}", 1)
				got := checkYAMLEdit(t, input, FixPathToValidYamlExpression("spec.hostNetwork", "false", 1), want)
				objects, err := cautils.ReadFile([]byte(got), cautils.YAML_FILE_FORMAT)
				require.NoError(t, err)
				require.Len(t, objects, 2)
				require.Equal(t, false, objects[1].GetObject()["spec"].(map[string]any)["hostNetwork"])
			})
		}
	}
	checkYAMLEdit(t, "spec:\r\n  old: true\r\n", `select(di==0).spec.new.nested |= false`, "spec:\r\n  old: true\r\n  new:\r\n    nested: false\r\n")
	checkYAMLEdit(t, "spec:\n  old: true", `select(di==0).spec.new |= false`, "spec:\n  old: true\n  new: false")
}

func TestYAMLTreeEditor_NonWorkloadClassification(t *testing.T) {
	for _, nonWorkload := range []string{"1: a\n", "? [one, two]\n: a\n"} {
		t.Run(nonWorkload, func(t *testing.T) {
			prefix := nonWorkload + "---\napiVersion: v1\nkind: Pod\nmetadata: {name: first}\nspec: {hostNetwork: true}\n---\n"
			target := "apiVersion: v1\nkind: Pod\nmetadata: {name: second}\nspec: {hostNetwork: true}\n"
			input := prefix + target
			docs, err := decodeDocumentRoots(input)
			require.NoError(t, err, "non-workload documents are valid YAML")
			require.Len(t, docs, 3)

			got, err := ApplyFixToContent(context.Background(), input, FixPathToValidYamlExpression("spec.hostNetwork", "false", 1))
			require.NoError(t, err)
			require.Equal(t, prefix+strings.Replace(target, "true", "false", 1), got)
			fixedDocs, err := decodeDocumentRoots(got)
			require.NoError(t, err)
			require.Len(t, fixedDocs, 3)
			var resource map[string]any
			require.NoError(t, fixedDocs[2].Decode(&resource))
			require.Equal(t, false, resource["spec"].(map[string]any)["hostNetwork"])

			// Without any workload, generic documents retain their fallback index.
			indices, err := yamlWorkloadDocuments(docs[:1])
			require.NoError(t, err)
			require.Equal(t, []int{0}, indices)
		})
	}
}

func TestYAMLTreeEditor_UntouchedConstructs(t *testing.T) {
	input := "# --- this is a real comment\nbase: &defaults {name: demo}\ncopy: *defaults\nmerged: {<<: *defaults}\nscript: |\n  echo ---\n  # literal comment\nquoted: '--- inside a scalar'\n\ntarget:   true  # note\n"
	checkYAMLEdit(t, input, `select(di==0).target |= false`, strings.Replace(input, "target:   true", "target:   false", 1))
}

func TestYAMLTreeEditor_DocumentMarkers(t *testing.T) {
	// No sanitizing placeholders: short inputs and real comments remain data.
	for _, input := range []string{"", "-", "--", "# -", "# --", "# ---", "# abc", "# ---\nkind: Pod\n", "---\napiVersion: v1\nkind: Pod\n"} {
		t.Run(input, func(t *testing.T) { checkYAMLEdit(t, input, "", input) })
	}
}

func TestYAMLTreeEditor_ProfileDriftValues(t *testing.T) {
	input := "apiVersion: v1\nkind: Pod\nmetadata: {name: demo}\nspec:\n  containers:\n  - name: app\n    image: nginx\n"
	fixes := DetectProfileDrift([]byte(input), &storagev1beta1.ContainerProfile{}, "Pod", "app", 0)
	require.Len(t, fixes, 2)
	expressions := []string{fixes[0].YamlExpression, fixes[1].YamlExpression}
	want := input + "    securityContext:\n      readOnlyRootFilesystem: true\n      capabilities:\n        drop:\n          - ALL\n"
	got := checkYAMLEdit(t, input, strings.Join(expressions, " | "), want)
	var obj map[string]any
	require.NoError(t, yaml.Unmarshal([]byte(got), &obj))
	container := obj["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
	sc := container["securityContext"].(map[string]any)
	require.Equal(t, true, sc["readOnlyRootFilesystem"])
	require.Equal(t, []any{"ALL"}, sc["capabilities"].(map[string]any)["drop"])
}

func TestYAMLTreeEditor_ExpressionValuesAreData(t *testing.T) {
	t.Setenv("YAML_EDITOR_SECRET", "fake-env-secret")
	secretFile := filepath.Join(t.TempDir(), "secret.txt")
	require.NoError(t, os.WriteFile(secretFile, []byte("fake-file-secret"), 0o600))
	values := []string{`[strenv(YAML_EDITOR_SECRET)]`, `load_str("` + secretFile + `")`, `[] | strenv(YAML_EDITOR_SECRET) | []`}
	for _, value := range values {
		got, err := ApplyFixToContent(context.Background(), "target: old\n", FixPathToValidYamlExpression("target", value, 0))
		require.NoError(t, err)
		var obj map[string]any
		require.NoError(t, yaml.Unmarshal([]byte(got), &obj))
		require.Equal(t, value, obj["target"])
		require.NotContains(t, got, "fake-env-secret")
		require.NotContains(t, got, "fake-file-secret")
	}
}

func TestYAMLTreeEditor_Errors(t *testing.T) {
	tests := []struct{ input, expression string }{
		{"spec: [", `select(di==0).spec.x |= false`},
		{"spec: {}\n", `select(di==1).spec.x |= false`},
		{"spec: {}\n", `select(di==-1).spec.x |= false`},
		{"args: [one]\n", `select(di==0).args[-1] |= "bad"`},
		{"args: [one]\n", `select(di==0).args[2] |= "bad"`},
		{"spec: true\n", `select(di==0).spec.child |= false`},
		{"spec: {}\n", `select(di==0).spec.x |= strenv(SECRET)`},
		{"spec: {}\n", `select(di==0).spec.x |= [strenv(SECRET)]`},
		{"spec: {}\n", `select(di==0).spec.x |= load_str("secret")`},
		{"spec: {}\n", `select(di==0).spec.x |= "one" + "two"`},
		{"spec: {}\n", `select(di==0).spec.x |= false | arbitrary()`},
		{"args: []\n", "select(di==0).args |= [\"one\"]\n---\n[\"two\"]"},
		{"base: &base {x: true}\ncopy: *base\n", `select(di==0).copy.x |= false`},
		{"base: &base {x: true}\ncopy: *base\n", `select(di==0).base.x |= false`},
		{"x: !!str old\n", `select(di==0).x |= "new"`},
		{"x: |\n  old\n", `select(di==0).x |= "new"`},
		{"apiVersion: v1\nkind: List\nitems: []\n", `select(di==0).spec.x |= false`},
	}
	for i, tt := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			got, err := ApplyFixToContent(context.Background(), tt.input, tt.expression)
			require.Error(t, err)
			require.Empty(t, got)
		})
	}
}

func TestYAMLTreeEditor_FileFailureIsAtomic(t *testing.T) {
	dir := t.TempDir()
	bad, good := filepath.Join(dir, "bad.yaml"), filepath.Join(dir, "good.yaml")
	input := "spec:\n  target: true\n  args: [one]\n"
	for _, p := range []string{bad, good} {
		require.NoError(t, os.WriteFile(p, []byte(input), 0o600))
	}
	resources := []ResourceFixInfo{
		{FilePath: bad, YamlExpressions: map[string]armotypes.FixPath{`select(di==0).spec.target |= false | select(di==0).spec.args[5] |= "bad"`: {}}},
		{FilePath: good, YamlExpressions: map[string]armotypes.FixPath{`select(di==0).spec.target |= false`: {}}},
	}
	h, err := NewFixHandlerMock()
	require.NoError(t, err)
	count, errs := h.ApplyChanges(context.Background(), resources)
	require.Equal(t, 1, count)
	require.Len(t, errs, 1)
	untouched, err := os.ReadFile(bad)
	require.NoError(t, err)
	require.Equal(t, input, string(untouched))
	fixed, err := os.ReadFile(good)
	require.NoError(t, err)
	require.Equal(t, strings.Replace(input, "target: true", "target: false", 1), string(fixed))
}

func TestYAMLTreeEditor_ReportApplicationUsesScannerIndex(t *testing.T) {
	dir := t.TempDir()
	input := "---\n# empty\n---\napiVersion: apps/v1\nkind: Deployment\nmetadata: {name: demo, namespace: default}\nspec:\n  replicas:   1 # keep\n"
	file := filepath.Join(dir, "deploy.yaml")
	require.NoError(t, os.WriteFile(file, []byte(input), 0o600))
	loaded, _, err := cautils.LoadResourcesFromFiles(context.Background(), file, dir, nil)
	require.NoError(t, err)
	require.Len(t, loaded[file], 1)
	resource := reporthandling.NewResource(loaded[file][0].GetObject())
	resource.Source = &reporthandling.Source{FileType: reporthandling.SourceTypeYaml, Path: dir, RelativePath: "deploy.yaml"}
	h := newHandlerForResources(dir, []resourcesresults.Result{{ResourceID: resource.GetID(), AssociatedControls: []resourcesresults.ResourceAssociatedControl{failedControl("C-1", "replicas", failedRuleWithFix("spec.replicas", "2"))}}}, []reporthandling.Resource{*resource}, true)
	fixes := h.PrepareResourcesToFix(context.Background())
	require.Len(t, fixes, 1)
	require.Equal(t, 0, fixes[0].DocumentIndex)
	count, errs := h.ApplyChanges(context.Background(), fixes)
	require.Empty(t, errs)
	require.Equal(t, 1, count)
	got, err := os.ReadFile(file)
	require.NoError(t, err)
	require.Equal(t, strings.Replace(input, "replicas:   1", "replicas:   2", 1), string(got))
	count, errs = h.ApplyChanges(context.Background(), fixes)
	require.Empty(t, errs)
	require.Equal(t, 1, count)
	second, err := os.ReadFile(file)
	require.NoError(t, err)
	require.Equal(t, got, second)
}
