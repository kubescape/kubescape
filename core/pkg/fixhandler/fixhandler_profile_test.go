package fixhandler

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	storagev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPrepareResourcesToFix_ProfileDrift(t *testing.T) {
	profile := storagev1beta1.ContainerProfile{
		TypeMeta: k8smetav1.TypeMeta{
			Kind: "ContainerProfile",
		},
		ObjectMeta: k8smetav1.ObjectMeta{
			Labels: map[string]string{
				"kubescape.io/workload-container-name": "app",
				"kubescape.io/workload-kind":           "Deployment",
				"kubescape.io/workload-name":           "myapp",
				"kubescape.io/workload-namespace":      "default",
			},
		},
		Spec: storagev1beta1.ContainerProfileSpec{
			Capabilities: []string{"NET_ADMIN", "SYS_TIME"},
		},
	}
	profileData, err := json.Marshal(profile)
	require.NoError(t, err)

	tmpDir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	profilePath := filepath.Join(tmpDir, "profile.json")
	require.NoError(t, os.WriteFile(profilePath, profileData, 0600))

	yamlPath := filepath.Join(tmpDir, "myapp.yaml")
	yamlContent := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
  namespace: default
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx`
	require.NoError(t, os.WriteFile(yamlPath, []byte(yamlContent), 0600))

	fixInfo := &metav1.FixInfo{
		BasePath:             tmpDir,
		ContainerProfilePath: profilePath,
	}

	var yamlObj map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"myapp","namespace":"default"},"spec":{"template":{"spec":{"containers":[{"name":"app","image":"nginx"}]}}},"sourcePath":"myapp.yaml:0"}`), &yamlObj))

	resourceObj := &reporthandling.Resource{
		Object: yamlObj,
		Source: &reporthandling.Source{
			Path:         tmpDir, // this is the key fix
			RelativePath: "myapp.yaml",
			FileType:     reporthandling.SourceTypeYaml,
		},
	}

	report := &reporthandlingv2.PostureReport{
		SummaryDetails: reportsummary.SummaryDetails{
			Controls: reportsummary.ControlSummaries{},
		},
		Resources: []reporthandling.Resource{*resourceObj},
		Results: []resourcesresults.Result{
			{
				ResourceID:  resourceObj.GetID(),
				RawResource: resourceObj,
				AssociatedControls: []resourcesresults.ResourceAssociatedControl{
					{
						ControlID: "C-0001",
						Status: apis.StatusInfo{
							InnerStatus: apis.StatusFailed,
						},
						ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
							{
								Status: apis.StatusFailed,
							},
						},
					},
				},
			},
		},
	}

	h := &FixHandler{
		fixInfo:       fixInfo,
		reportObj:     report,
		localBasePath: tmpDir,
	}

	fixes := h.PrepareResourcesToFix(context.Background())
	require.Len(t, fixes, 1)
	assert.Greater(t, len(fixes[0].YamlExpressions), 0) // Should have seccomp fix from drift

	// 3. Setup with mismatched namespace
	var yamlObj2 map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"myapp","namespace":"other"},"spec":{"template":{"spec":{"containers":[{"name":"app","image":"nginx"}]}}},"sourcePath":"myapp.yaml:0"}`), &yamlObj2))

	resourceObj2 := &reporthandling.Resource{
		Object: yamlObj2,
		Source: &reporthandling.Source{
			Path:         tmpDir,
			RelativePath: "myapp.yaml",
			FileType:     reporthandling.SourceTypeYaml,
		},
	}

	report2 := &reporthandlingv2.PostureReport{
		Resources: []reporthandling.Resource{*resourceObj2},
		Results: []resourcesresults.Result{
			{
				ResourceID:  resourceObj2.GetID(),
				RawResource: resourceObj2,
				AssociatedControls: []resourcesresults.ResourceAssociatedControl{
					{
						ControlID: "C-0001",
						Status: apis.StatusInfo{
							InnerStatus: apis.StatusFailed,
						},
						ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
							{
								Status: apis.StatusFailed,
							},
						},
					},
				},
			},
		},
	}

	h2 := &FixHandler{
		fixInfo:       fixInfo,
		reportObj:     report2,
		localBasePath: tmpDir,
	}

	fixes2 := h2.PrepareResourcesToFix(context.Background())
	assert.Len(t, fixes2, 0)
}
