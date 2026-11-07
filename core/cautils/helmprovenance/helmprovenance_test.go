package helmprovenance

import (
	"reflect"
	"testing"

	"helm.sh/helm/v3/pkg/chart"
)

func tmpl(name, body string) *chart.File {
	return &chart.File{Name: name, Data: []byte(body)}
}

func newChart(name string, files ...*chart.File) *chart.Chart {
	c := &chart.Chart{
		Metadata:  &chart.Metadata{Name: name, Version: "0.0.0"},
		Templates: files,
	}
	return c
}

// Direct .Values refs, range, with, whitespace-trimmed actions.
func TestExtract_DirectRefs(t *testing.T) {
	c := newChart("app", tmpl("templates/deployment.yaml", `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Values.name }}
spec:
  replicas: {{- .Values.replicaCount }}
  template:
    spec:
      containers:
      {{- range .Values.containers }}
        - name: {{ .name }}
          image: "{{ .Values.image.repo }}:{{ .Values.image.tag }}"
      {{- end }}
`))
	got := Extract(c)
	prov, ok := got["app/templates/deployment.yaml"]
	if !ok {
		t.Fatalf("missing key, got=%v", got)
	}
	want := []string{"containers", "image.repo", "image.tag", "name", "replicaCount"}
	if !reflect.DeepEqual(prov.ValuesPaths, want) {
		t.Errorf("ValuesPaths = %v, want %v", prov.ValuesPaths, want)
	}
	if prov.TemplateLine != 2 {
		t.Errorf("TemplateLine = %d, want 2", prov.TemplateLine)
	}
}

// Partials: refs inside _helpers.tpl propagate to templates that include them.
func TestExtract_PartialIncludes(t *testing.T) {
	c := newChart("app",
		tmpl("templates/_helpers.tpl", `
{{- define "app.labels" -}}
app: {{ .Values.appName }}
version: {{ .Values.version }}
{{- end -}}

{{- define "app.fullname" -}}
{{ include "app.labels" . }}
fullname: {{ .Values.fullnameOverride }}
{{- end -}}
`),
		tmpl("templates/svc.yaml", `
apiVersion: v1
kind: Service
metadata:
  name: {{ include "app.fullname" . }}
  labels:
    {{- include "app.labels" . | nindent 4 }}
`),
	)
	got := Extract(c)
	prov := got["app/templates/svc.yaml"]
	want := []string{"appName", "fullnameOverride", "version"}
	if !reflect.DeepEqual(prov.ValuesPaths, want) {
		t.Errorf("ValuesPaths = %v, want %v", prov.ValuesPaths, want)
	}
	// _helpers.tpl is a partial, must not appear as its own entry.
	if _, present := got["app/templates/_helpers.tpl"]; present {
		t.Errorf("partial _helpers.tpl should not appear as a rendered key")
	}
}

// Index-style access: (index .Values "foo" "bar.baz") flattens to foo.bar.baz.
func TestExtract_IndexAccess(t *testing.T) {
	c := newChart("app", tmpl("templates/cm.yaml", `
apiVersion: v1
kind: ConfigMap
data:
  k: {{ index .Values "global" "registry" }}
  n: {{ .Values.replicaCount }}
`))
	got := Extract(c)["app/templates/cm.yaml"]
	want := []string{"global.registry", "replicaCount"}
	if !reflect.DeepEqual(got.ValuesPaths, want) {
		t.Errorf("ValuesPaths = %v, want %v", got.ValuesPaths, want)
	}
}

// Subcharts: rendered key must mirror Helm engine's `<root>/charts/<sub>/...`.
func TestExtract_Subchart(t *testing.T) {
	sub := newChart("redis", tmpl("templates/master.yaml", `
apiVersion: apps/v1
kind: StatefulSet
spec:
  replicas: {{ .Values.master.replicaCount }}
`))
	root := newChart("app", tmpl("templates/deployment.yaml", `
apiVersion: apps/v1
kind: Deployment
`))
	root.AddDependency(sub)

	got := Extract(root)
	if _, ok := got["app/charts/redis/templates/master.yaml"]; !ok {
		t.Errorf("missing subchart key, got=%v", got)
	}
	if _, ok := got["app/templates/deployment.yaml"]; !ok {
		t.Errorf("missing root key, got=%v", got)
	}
}

// Recursive-include partials must not loop forever.
func TestExtract_RecursivePartial(t *testing.T) {
	c := newChart("app",
		tmpl("templates/_helpers.tpl", `
{{- define "a" -}}
{{ include "b" . }} {{ .Values.fromA }}
{{- end -}}
{{- define "b" -}}
{{ include "a" . }} {{ .Values.fromB }}
{{- end -}}
`),
		tmpl("templates/x.yaml", `
apiVersion: v1
kind: ConfigMap
data:
  v: {{ include "a" . }}
`),
	)
	got := Extract(c)["app/templates/x.yaml"]
	want := []string{"fromA", "fromB"}
	if !reflect.DeepEqual(got.ValuesPaths, want) {
		t.Errorf("ValuesPaths = %v, want %v", got.ValuesPaths, want)
	}
}

// Defines that contain nested {{ if }} / {{ range }} / {{ with }} blocks
// previously had their bodies truncated at the first inner {{ end }} by the
// old single-regex matcher, dropping any .Values references after that point.
// The depth-tracked findDefines must capture the whole body.
func TestExtract_DefineWithNestedControlFlow(t *testing.T) {
	c := newChart("app",
		tmpl("templates/_helpers.tpl", `
{{- define "app.labels" -}}
{{- if .Values.useExtra }}
extra: {{ .Values.extra }}
{{- end }}
{{- range .Values.envs }}
- name: {{ .name }}
{{- end }}
{{- with .Values.nodeSelector }}
nodeSelector:
  {{ toYaml . | nindent 2 }}
{{- end }}
app: {{ .Values.appName }}
version: {{ .Values.version }}
{{- end -}}
`),
		tmpl("templates/svc.yaml", `
apiVersion: v1
kind: Service
metadata:
  labels:
    {{- include "app.labels" . | nindent 4 }}
`),
	)
	got := Extract(c)["app/templates/svc.yaml"]
	// All five .Values.* references inside the define must be picked up,
	// including the ones that appear *after* the nested control blocks.
	want := []string{"appName", "envs", "extra", "nodeSelector", "useExtra", "version"}
	if !reflect.DeepEqual(got.ValuesPaths, want) {
		t.Errorf("ValuesPaths = %v, want %v", got.ValuesPaths, want)
	}
}

// Multiple defines in one file must all be captured, and an {{ end }} from a
// nested block inside the first define must not be mis-attributed to it.
func TestExtract_MultipleDefinesWithNesting(t *testing.T) {
	c := newChart("app",
		tmpl("templates/_helpers.tpl", `
{{- define "a" -}}
{{- if .Values.flagA }}{{ .Values.fromA }}{{- end }}
trail: {{ .Values.trailA }}
{{- end -}}

{{- define "b" -}}
{{- range .Values.itemsB }}{{ . }}{{- end }}
trail: {{ .Values.trailB }}
{{- end -}}
`),
		tmpl("templates/x.yaml", `
apiVersion: v1
kind: ConfigMap
data:
  a: {{ include "a" . }}
  b: {{ include "b" . }}
`),
	)
	got := Extract(c)["app/templates/x.yaml"]
	want := []string{"flagA", "fromA", "itemsB", "trailA", "trailB"}
	if !reflect.DeepEqual(got.ValuesPaths, want) {
		t.Errorf("ValuesPaths = %v, want %v", got.ValuesPaths, want)
	}
}

// findDefines must terminate when an unbalanced {{ end }} appears (a malformed
// template should not panic or loop). We don't assert specific output — only
// that the call returns.
func TestFindDefines_UnbalancedDoesNotPanic(t *testing.T) {
	_ = findDefines([]byte(`
{{- define "x" -}}
{{- if .Values.foo }}body{{- end }}
{{- end -}}
{{- end -}}  {{/* stray end */}}
`))
}

// A with block rebinds dot, so relative field references are nested below
// the .Values path used to open the block.
func TestExtract_WithBlockRebinding(t *testing.T) {
	c := newChart("app", tmpl("templates/cm.yaml", `
apiVersion: v1
kind: ConfigMap
data:
  {{- with .Values.image }}
  repo: {{ .repo }}
  {{- if $.Values.useMirror }}
  mirror: {{ .mirror }}
  {{- end }}
  {{- end }}
  name: {{ .Values.name }}
`))
	got := Extract(c)["app/templates/cm.yaml"]
	want := []string{"image", "image.mirror", "image.repo", "name", "useMirror"}
	if !reflect.DeepEqual(got.ValuesPaths, want) {
		t.Errorf("ValuesPaths = %v, want %v", got.ValuesPaths, want)
	}
}

func TestExtract_WithBlockElseRestoresParentScope(t *testing.T) {
	c := newChart("app", tmpl("templates/cm.yaml", `
apiVersion: v1
kind: ConfigMap
data:
  {{- with .Values.parent }}
    {{- with .child }}
  child: {{ .childField }}
    {{- else }}
  parent: {{ .parentField }}
    {{- end }}
  {{- end }}
`))
	got := Extract(c)["app/templates/cm.yaml"]
	want := []string{"parent", "parent.child", "parent.child.childField", "parent.parentField"}
	if !reflect.DeepEqual(got.ValuesPaths, want) {
		t.Errorf("ValuesPaths = %v, want %v", got.ValuesPaths, want)
	}
}

func TestExtract_WithBlockDoesNotLeakScopeThroughElseIf(t *testing.T) {
	c := newChart("app", tmpl("templates/cm.yaml", `
apiVersion: v1
kind: ConfigMap
data:
  {{- with .Values.image }}
    {{- if .enabled }}a{{- else if .fallback }}b{{- end }}
  {{- end }}
  release: {{ $.Release.Name }}
  other: {{ $other.repo }}
`))
	got := Extract(c)["app/templates/cm.yaml"]
	want := []string{"image", "image.enabled", "image.fallback"}
	if !reflect.DeepEqual(got.ValuesPaths, want) {
		t.Errorf("ValuesPaths = %v, want %v", got.ValuesPaths, want)
	}
}

func TestExtract_WithBlockScopeOperands(t *testing.T) {
	c := newChart("app", tmpl("templates/cm.yaml", `
apiVersion: v1
kind: ConfigMap
data:
  {{- with .Values.image }}
    {{- with . }}
  same: {{ .same }}
    {{- end }}
    {{- with dict "key" .Values.other }}
  repo: {{ .repo }}
    {{- end }}
    {{- with index .Values.nested "image" }}
  tag: {{ .tag }}
    {{- end }}
  text: {{ printf "dotted.string" .quoted }}
  {{- end }}
`))
	got := Extract(c)["app/templates/cm.yaml"]
	want := []string{"image", "image.quoted", "image.same", "nested", "other"}
	if !reflect.DeepEqual(got.ValuesPaths, want) {
		t.Errorf("ValuesPaths = %v, want %v", got.ValuesPaths, want)
	}
}

// Empty chart and nil chart should not panic.
func TestExtract_NilAndEmpty(t *testing.T) {
	if got := Extract(nil); got != nil {
		t.Errorf("Extract(nil) = %v, want nil", got)
	}
	if got := Extract(newChart("empty")); len(got) != 0 {
		t.Errorf("Extract(empty chart) = %v, want empty", got)
	}
}
