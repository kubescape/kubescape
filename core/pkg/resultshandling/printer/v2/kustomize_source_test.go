package printer

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A Kustomize resource is attributed to the file Kustomize read it from, but it
// has no document index: its own path is the Kustomize directory. When no source
// file or uncomposed field can be resolved, the table must name the file and
// must not invent a line for it.
func TestResourceTableNamesTheKustomizeOriginFileWithoutALine(t *testing.T) {
	session := resourceTableLineNumberSession(t, lineNumberManifest, "")

	out := renderResourceTable(t, session, true)

	assert.Contains(t, out, "Source: deploy.yaml")
	assert.Contains(t, out, "@ deploy.yaml")
	assert.Contains(t, out, "privileged=false")
	assert.NotContains(t, out, "(line ", "no line is reported for a resource without a document index")
}

func kustomizeTestSession(t *testing.T, baseManifest string, renderedObj map[string]any, paths []armotypes.PosturePaths) *cautils.OPASessionObj {
	t.Helper()
	dir := t.TempDir()
	baseFile := filepath.Join(dir, "base", "deployment.yaml")
	require.NoError(t, os.MkdirAll(filepath.Dir(baseFile), 0o755))
	require.NoError(t, os.WriteFile(baseFile, []byte(baseManifest), 0o600))

	resourceID := "apps/v1/default/Deployment/demo"
	lw := localworkload.NewLocalWorkload(renderedObj)
	lw.SetPath(filepath.Join(dir, "overlay"))

	session := cautils.NewOPASessionObjMock()
	session.ResourceSource = make(map[string]reporthandling.Source)
	session.AllResources[resourceID] = lw
	session.ResourceSource[resourceID] = reporthandling.Source{
		Path:                   dir,
		RelativePath:           filepath.Join("base", "deployment.yaml"),
		FileType:               reporthandling.SourceTypeKustomizeDirectory,
		KustomizeDirectoryName: filepath.Join(dir, "overlay"),
	}
	session.ResourcesResult[resourceID] = resourcesresults.Result{
		ResourceID: resourceID,
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{
			{
				ControlID: "C-0001",
				Name:      "Test Control",
				Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
				ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
					{
						Name:   "test-rule",
						Status: apis.StatusFailed,
						Paths:  paths,
					},
				},
			},
		},
	}
	session.Report.SummaryDetails = reportsummary.SummaryDetails{
		Controls: reportsummary.ControlSummaries{
			"C-0001": {ControlID: "C-0001", Name: "Test Control", ScoreFactor: 8.0},
		},
	}
	return session
}

func TestResourceTable_KustomizeUncomposedFieldResolvesLine(t *testing.T) {
	baseManifest := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
  namespace: default
spec:
  template:
    spec:
      hostNetwork: true
      containers:
      - name: app
        image: nginx:1
        securityContext:
          privileged: true
`
	renderedObj := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name":      "demo",
			"namespace": "default",
		},
		"spec": map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"hostNetwork": true,
					"containers": []any{
						map[string]any{
							"name":  "app",
							"image": "nginx:1",
							"securityContext": map[string]any{
								"privileged": true,
							},
						},
					},
				},
			},
		},
	}

	paths := []armotypes.PosturePaths{
		{DeletePath: "spec.template.spec.hostNetwork"},
		{FixPath: armotypes.FixPath{
			Path:  "spec.template.spec.containers[0].securityContext.privileged",
			Value: "false",
		}},
	}

	session := kustomizeTestSession(t, baseManifest, renderedObj, paths)
	out := renderResourceTable(t, session, true)

	assert.Contains(t, out, "Source: base")
	assert.Contains(t, out, "spec.template.spec.hostNetwork (current: true) (line 9)")
	assert.Contains(t, out, "spec.template.spec.containers[0].securityContext.privileged=false (app) (line 14)")
}

func TestResourceTable_KustomizeComposedFieldKeepsFileOnly(t *testing.T) {
	baseManifest := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
  namespace: default
spec:
  replicas: 1
`
	renderedObj := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name":      "demo",
			"namespace": "default",
		},
		"spec": map[string]any{
			"replicas": 3, // Patched by overlay
		},
	}

	paths := []armotypes.PosturePaths{
		{ReviewPath: "spec.replicas"},
	}

	session := kustomizeTestSession(t, baseManifest, renderedObj, paths)
	out := renderResourceTable(t, session, true)

	assert.Contains(t, out, "Source: base")
	assert.Contains(t, out, "spec.replicas (current: 3)")
	assert.NotContains(t, out, "(line ", "patched/composed field must not invent a line number")
}

func TestResourceTable_KustomizeOverlayAddedFieldKeepsFileOnly(t *testing.T) {
	baseManifest := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
  namespace: default
spec:
  replicas: 1
`
	renderedObj := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name":      "demo",
			"namespace": "default",
		},
		"spec": map[string]any{
			"replicas": 1,
			"template": map[string]any{
				"spec": map[string]any{
					"hostNetwork": true, // Added by overlay
				},
			},
		},
	}

	paths := []armotypes.PosturePaths{
		{DeletePath: "spec.template.spec.hostNetwork"},
	}

	session := kustomizeTestSession(t, baseManifest, renderedObj, paths)
	out := renderResourceTable(t, session, true)

	assert.Contains(t, out, "Source: base")
	assert.Contains(t, out, "spec.template.spec.hostNetwork")
	assert.NotContains(t, out, "(line ", "field added by overlay must not invent a line number")
}

func TestResourceTable_KustomizeOverlayAddedContainerFixPathKeepsFileOnly(t *testing.T) {
	baseManifest := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
  namespace: default
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx:1
`
	renderedObj := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name":      "demo",
			"namespace": "default",
		},
		"spec": map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"containers": []any{
						map[string]any{"name": "app", "image": "nginx:1"},
						map[string]any{"name": "sidecar", "image": "busybox:1"}, // Added by overlay
					},
				},
			},
		},
	}

	paths := []armotypes.PosturePaths{
		{FixPath: armotypes.FixPath{
			Path:  "spec.template.spec.containers[1].securityContext.privileged",
			Value: "false",
		}},
	}

	session := kustomizeTestSession(t, baseManifest, renderedObj, paths)
	out := renderResourceTable(t, session, true)

	assert.Contains(t, out, "Source: base")
	assert.Contains(t, out, "privileged=false (sidecar)")
	assert.NotContains(t, out, "(line ", "fix on overlay-added container must not invent a line number")
}

func TestResourceTable_HelmTemplateWithActionsResolvesStaticFieldsAndOmitsTemplated(t *testing.T) {
	dir := t.TempDir()
	templateFile := filepath.Join(dir, "templates", "deployment.yaml")
	require.NoError(t, os.MkdirAll(filepath.Dir(templateFile), 0o755))

	rawTemplate := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
  namespace: default
spec:
  template:
    spec:
      hostNetwork: true
      containers:
      - name: app
        image: "{{ .Values.image }}"
`
	require.NoError(t, os.WriteFile(templateFile, []byte(rawTemplate), 0o600))

	resourceID := "apps/v1/default/Deployment/demo"
	renderedObj := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name":      "demo",
			"namespace": "default",
		},
		"spec": map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"hostNetwork": true,
					"containers": []any{
						map[string]any{
							"name":  "app",
							"image": "nginx:1.25",
						},
					},
				},
			},
		},
	}

	lw := localworkload.NewLocalWorkload(renderedObj)
	lw.SetPath(filepath.Join(dir, "templates", "deployment.yaml")) // No :<index> suffix

	session := cautils.NewOPASessionObjMock()
	session.ResourceSource = make(map[string]reporthandling.Source)
	session.AllResources[resourceID] = lw
	session.ResourceSource[resourceID] = reporthandling.Source{
		Path:         dir,
		RelativePath: filepath.Join("templates", "deployment.yaml"),
		FileType:     reporthandling.SourceTypeHelmChart,
	}
	session.ResourcesResult[resourceID] = resourcesresults.Result{
		ResourceID: resourceID,
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{
			{
				ControlID: "C-0001",
				Name:      "Test Control",
				Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
				ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
					{
						Name:   "test-rule",
						Status: apis.StatusFailed,
						Paths: []armotypes.PosturePaths{
							{DeletePath: "spec.template.spec.hostNetwork"},
							{ReviewPath: "spec.template.spec.containers[0].image"},
						},
					},
				},
			},
		},
	}
	session.Report.SummaryDetails = reportsummary.SummaryDetails{
		Controls: reportsummary.ControlSummaries{
			"C-0001": {ControlID: "C-0001", Name: "Test Control", ScoreFactor: 8.0},
		},
	}

	out := renderResourceTable(t, session, true)

	// Static field resolves line in template
	assert.Contains(t, out, "spec.template.spec.hostNetwork (current: true) (line 9)")
	// Templated field prints current value but omits line number
	assert.Contains(t, out, "spec.template.spec.containers[0].image (current: nginx:1.25) (app)")
	assert.NotRegexp(t, regexp.MustCompile(`spec\.template\.spec\.containers\[0\]\.image.*\(line `), out)
}

func TestResourceTable_HelmTemplateInvalidYAMLDegradesGracefully(t *testing.T) {
	dir := t.TempDir()
	templateFile := filepath.Join(dir, "templates", "deployment.yaml")
	require.NoError(t, os.MkdirAll(filepath.Dir(templateFile), 0o755))

	// Invalid YAML due to unquoted action
	rawTemplate := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
  namespace: default
spec:
  replicas: {{ .Values.replicas }}
`
	require.NoError(t, os.WriteFile(templateFile, []byte(rawTemplate), 0o600))

	resourceID := "apps/v1/default/Deployment/demo"
	renderedObj := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name":      "demo",
			"namespace": "default",
		},
		"spec": map[string]any{
			"replicas": 3,
		},
	}

	lw := localworkload.NewLocalWorkload(renderedObj)
	lw.SetPath(filepath.Join(dir, "templates", "deployment.yaml"))

	session := cautils.NewOPASessionObjMock()
	session.ResourceSource = make(map[string]reporthandling.Source)
	session.AllResources[resourceID] = lw
	session.ResourceSource[resourceID] = reporthandling.Source{
		Path:         dir,
		RelativePath: filepath.Join("templates", "deployment.yaml"),
		FileType:     reporthandling.SourceTypeHelmChart,
	}
	session.ResourcesResult[resourceID] = resourcesresults.Result{
		ResourceID: resourceID,
		AssociatedControls: []resourcesresults.ResourceAssociatedControl{
			{
				ControlID: "C-0001",
				Name:      "Test Control",
				Status:    apis.StatusInfo{InnerStatus: apis.StatusFailed},
				ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
					{
						Name:   "test-rule",
						Status: apis.StatusFailed,
						Paths: []armotypes.PosturePaths{
							{ReviewPath: "spec.replicas"},
						},
					},
				},
			},
		},
	}
	session.Report.SummaryDetails = reportsummary.SummaryDetails{
		Controls: reportsummary.ControlSummaries{
			"C-0001": {ControlID: "C-0001", Name: "Test Control", ScoreFactor: 8.0},
		},
	}

	out := renderResourceTable(t, session, true)

	assert.Contains(t, out, "spec.replicas (current: 3)")
	assert.NotContains(t, out, "(line ", "unparseable template YAML must degrade gracefully without line")
}

