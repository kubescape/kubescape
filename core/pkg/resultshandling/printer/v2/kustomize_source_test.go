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
	corev1 "k8s.io/api/core/v1"
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

// When a field of a rendered resource can be traced to an overlay patch, the evidence
// names the patching file next to the base file (e.g. "@ base/deploy.yaml (patch: overlay/patch.yaml)").
func TestResourceTableNamesOverlayPatchInEvidence(t *testing.T) {
	root := t.TempDir()
	overlayDir := filepath.Join(root, "overlay")
	require.NoError(t, os.MkdirAll(overlayDir, 0o755))

	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "kustomization.yaml"), []byte(`
resources:
- ../base
patches:
- path: patch.yaml
  target:
    kind: Deployment
    name: demo
`), 0o600))

	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "patch.yaml"), []byte(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
spec:
  template:
    spec:
      containers:
      - name: nginx
        securityContext:
          privileged: true
`), 0o600))

	session := resourceTableLineNumberSession(t, lineNumberManifest, "")
	resourceID := "apps/v1/default/Deployment/demo"
	session.ResourceSource[resourceID] = reporthandling.Source{
		Path:                   root,
		RelativePath:           "base/deploy.yaml",
		FileType:               reporthandling.SourceTypeKustomizeDirectory,
		KustomizeDirectoryName: overlayDir,
	}

	out := renderResourceTable(t, session, true)

	assert.Contains(t, out, "Source: base/deploy.yaml")
	assert.Contains(t, out, "@ base/deploy.yaml (patch: overlay/patch.yaml)")
	assert.Contains(t, out, "privileged=false")
	assert.NotContains(t, out, "(line ")
}

// Where a field cannot be traced to a patch, today's behavior of naming only the base file
// in the evidence is preserved.
func TestResourceTableUnpatchedFieldKeepsBaseFileOnly(t *testing.T) {
	root := t.TempDir()
	overlayDir := filepath.Join(root, "overlay")
	require.NoError(t, os.MkdirAll(overlayDir, 0o755))

	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "kustomization.yaml"), []byte(`
resources:
- ../base
patches:
- path: patch.yaml
  target:
    kind: Deployment
    name: demo
`), 0o600))

	// patch only touches replicas, not the privileged field
	require.NoError(t, os.WriteFile(filepath.Join(overlayDir, "patch.yaml"), []byte(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
spec:
  replicas: 3
`), 0o600))

	session := resourceTableLineNumberSession(t, lineNumberManifest, "")
	resourceID := "apps/v1/default/Deployment/demo"
	session.ResourceSource[resourceID] = reporthandling.Source{
		Path:                   root,
		RelativePath:           "base/deploy.yaml",
		FileType:               reporthandling.SourceTypeKustomizeDirectory,
		KustomizeDirectoryName: overlayDir,
	}

	out := renderResourceTable(t, session, true)

	assert.Contains(t, out, "Source: base/deploy.yaml")
	assert.Contains(t, out, "@ base/deploy.yaml")
	assert.NotContains(t, out, "(patch:")
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

func TestResourceTable_KustomizeLeadingCommentDocumentResolvesCorrectLine(t *testing.T) {
	baseManifest := `# Leading comment document
---
apiVersion: apps/v1
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
						map[string]any{"name": "app", "image": "nginx:1"},
					},
				},
			},
		},
	}

	paths := []armotypes.PosturePaths{
		{DeletePath: "spec.template.spec.hostNetwork"},
	}

	session := kustomizeTestSession(t, baseManifest, renderedObj, paths)
	out := renderResourceTable(t, session, true)

	assert.Contains(t, out, "spec.template.spec.hostNetwork (current: true) (line 11)")
}

func TestResourceTable_KustomizeRemovedFieldByOverlayOmitsLine(t *testing.T) {
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
        securityContext:
          privileged: true
          capabilities: {}
`
	// The overlay removed privileged and capabilities, leaving securityContext: {}.
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
						map[string]any{
							"name":            "app",
							"image":           "nginx:1",
							"securityContext": map[string]any{},
						},
					},
				},
			},
		},
	}

	paths := []armotypes.PosturePaths{
		{DeletePath: "spec.template.spec.containers[0].securityContext.privileged"},
		{FixPath: armotypes.FixPath{Path: "spec.template.spec.containers[0].securityContext.capabilities.drop", Value: "ALL"}},
	}

	session := kustomizeTestSession(t, baseManifest, renderedObj, paths)
	out := renderResourceTable(t, session, true)

	assert.Contains(t, out, "spec.template.spec.containers[0].securityContext.privileged")
	assert.Contains(t, out, "spec.template.spec.containers[0].securityContext.capabilities.drop=ALL")
	assert.Contains(t, out, "@ base/deployment.yaml")
	assert.NotContains(t, out, "(line ", "an overlay removed the field or its nearest source ancestor")
}

func TestResourceTable_KustomizeReorderedContainersWithEqualLeavesOmitsLine(t *testing.T) {
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
        imagePullPolicy: Always
      - name: sidecar
        image: log-agent:1
        imagePullPolicy: Always
`
	// Overlay reordered containers: [sidecar, app]
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
						map[string]any{
							"name":            "sidecar",
							"image":           "log-agent:1",
							"imagePullPolicy": "Always",
						},
						map[string]any{
							"name":            "app",
							"image":           "nginx:1",
							"imagePullPolicy": "Always",
						},
					},
				},
			},
		},
	}

	// Finding is on containers[0].imagePullPolicy (which is sidecar in rendered, but app in base)
	paths := []armotypes.PosturePaths{
		{ReviewPath: "spec.template.spec.containers[0].imagePullPolicy"},
	}

	session := kustomizeTestSession(t, baseManifest, renderedObj, paths)
	out := renderResourceTable(t, session, true)

	assert.Contains(t, out, "spec.template.spec.containers[0].imagePullPolicy (current: Always) (sidecar)")
	assert.NotContains(t, out, "(line ", "reordered container must not attribute the other container's line")
}

func TestResourceTable_KustomizeCRDSchemaMapNameNoPanic(t *testing.T) {
	baseManifest := `apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: crontabs.stable.example.com
spec:
  group: stable.example.com
  names:
    kind: CronTab
  versions:
  - name: v1
    schema:
      openAPIV3Schema:
        properties:
          name:
            type: string
`
	renderedObj := map[string]any{
		"apiVersion": "apiextensions.k8s.io/v1",
		"kind":       "CustomResourceDefinition",
		"metadata": map[string]any{
			"name": "crontabs.stable.example.com",
		},
		"spec": map[string]any{
			"group": "stable.example.com",
			"names": map[string]any{
				"kind": "CronTab",
			},
			"versions": []any{
				map[string]any{
					"name": "v1",
					"schema": map[string]any{
						"openAPIV3Schema": map[string]any{
							"properties": map[string]any{
								"name": map[string]any{
									"type": "string",
								},
							},
						},
					},
				},
			},
		},
	}

	paths := []armotypes.PosturePaths{
		{ReviewPath: "spec.versions[0].schema.openAPIV3Schema.properties.name.type"},
	}

	session := kustomizeTestSession(t, baseManifest, renderedObj, paths)
	// Must not panic when evaluating rawMap["name"] where "name" holds a map schema
	assert.NotPanics(t, func() {
		out := renderResourceTable(t, session, true)
		assert.Contains(t, out, "spec.versions[0].schema.openAPIV3Schema.properties.name.type")
	})
}

func TestResourceTable_KustomizeReorderedUnnamedListEntriesNoMisattribution(t *testing.T) {
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
        ports:
        - containerPort: 80
          protocol: TCP
        - containerPort: 443
          protocol: TCP
`
	// Overlay reversed unnamed port entries: [443, 80]
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
						map[string]any{
							"name":  "app",
							"image": "nginx:1",
							"ports": []any{
								map[string]any{
									"containerPort": 443,
									"protocol":      "TCP",
								},
								map[string]any{
									"containerPort": 80,
									"protocol":      "TCP",
								},
							},
						},
					},
				},
			},
		},
	}

	// Finding is on ports[0].protocol (which is port 443 in rendered, but port 80 in base)
	paths := []armotypes.PosturePaths{
		{ReviewPath: "spec.template.spec.containers[0].ports[0].protocol"},
	}

	session := kustomizeTestSession(t, baseManifest, renderedObj, paths)
	out := renderResourceTable(t, session, true)

	assert.Contains(t, out, "spec.template.spec.containers[0].ports[0].protocol (current: TCP) (app)")
	assert.NotContains(t, out, "(line ", "reordered unnamed port must not attribute the other port's line")
}

// The scan writes containers back into the object as []corev1.Container
// (opaprocessor.removePodData). A container field that comes straight from the
// base file must still resolve to its line, like the pod-level field next to it.
func TestResourceTable_KustomizeTypedContainersResolveLine(t *testing.T) {
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
	privileged := true
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
					"containers": []corev1.Container{{
						Name:            "app",
						Image:           "nginx:1",
						SecurityContext: &corev1.SecurityContext{Privileged: &privileged},
					}},
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
		{FixPath: armotypes.FixPath{
			Path:  "spec.template.spec.containers[0].securityContext.runAsNonRoot",
			Value: "true",
		}},
		{FixPath: armotypes.FixPath{
			Path:  "spec.template.spec.containers[0].resources.limits.cpu",
			Value: "YOUR_VALUE",
		}},
	}

	session := kustomizeTestSession(t, baseManifest, renderedObj, paths)
	out := renderResourceTable(t, session, true)

	assert.Contains(t, out, "spec.template.spec.hostNetwork (current: true) (line 9)")
	assert.Contains(t, out, "spec.template.spec.containers[0].securityContext.privileged=false (app) (line 14)")
	assert.Contains(t, out, "spec.template.spec.containers[0].securityContext.runAsNonRoot=true (app) (line 14)")
	// The typed container encodes resources as {} although the base has none.
	assert.Contains(t, out, "spec.template.spec.containers[0].resources.limits.cpu=YOUR_VALUE (app) (line 11)")
}

// An overlay that removes a container's resources still leaves resources: {} in
// the typed container, so the base's resources block must not stand in as the
// nearest ancestor: its first line is gone from the rendered object.
func TestResourceTable_KustomizeTypedContainerRemovedResourcesOmitsLine(t *testing.T) {
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
        resources:
          limits:
            memory: 128Mi
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
					"containers": []corev1.Container{{Name: "app", Image: "nginx:1"}},
				},
			},
		},
	}

	paths := []armotypes.PosturePaths{
		{FixPath: armotypes.FixPath{
			Path:  "spec.template.spec.containers[0].resources.requests.cpu",
			Value: "YOUR_VALUE",
		}},
		{FixPath: armotypes.FixPath{
			Path:  "spec.template.spec.containers[0].resources.limits.cpu",
			Value: "YOUR_VALUE",
		}},
	}

	session := kustomizeTestSession(t, baseManifest, renderedObj, paths)
	out := renderResourceTable(t, session, true)

	assert.Contains(t, out, "spec.template.spec.containers[0].resources.requests.cpu=YOUR_VALUE (app)")
	assert.Contains(t, out, "spec.template.spec.containers[0].resources.limits.cpu=YOUR_VALUE (app)")
	assert.NotContains(t, out, "(line ", "the overlay removed the resources block")
}
