package anonymizer

import (
	"testing"

	"errors"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/cautils"
	"github.com/kubescape/kubescape/v3/core/pkg/reportcrypto"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/apis"
	"github.com/kubescape/opa-utils/reporthandling/attacktrack/v1alpha1"
	helpersv1 "github.com/kubescape/opa-utils/reporthandling/helpers/v1"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/prioritization"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type failingTransformer struct{}

func (f *failingTransformer) Transform(prefix string, value string) (string, error) {
	return "", errors.New("transform failed")
}

type metadataOnly struct{}

func (m *metadataOnly) SetNamespace(string)        {}
func (m *metadataOnly) SetName(string)             {}
func (m *metadataOnly) SetKind(string)             {}
func (m *metadataOnly) SetWorkload(map[string]any) {}
func (m *metadataOnly) SetObject(map[string]any)   {}
func (m *metadataOnly) SetApiVersion(string)       {}

func (m *metadataOnly) GetNamespace() string        { return "" }
func (m *metadataOnly) GetName() string             { return "" }
func (m *metadataOnly) GetKind() string             { return "" }
func (m *metadataOnly) GetApiVersion() string       { return "" }
func (m *metadataOnly) GetWorkload() map[string]any { return nil }
func (m *metadataOnly) GetObject() map[string]any   { return nil }
func (m *metadataOnly) GetID() string               { return "metadata-only" }

func (m *metadataOnly) GetObjectType() workloadinterface.ObjectType {
	return workloadinterface.ObjectType("metadataOnly")
}

func TestResolveMappedID(t *testing.T) {
	tests := []struct {
		name      string
		idMapping map[string]string
		original  string
		validate  func(t *testing.T, result string)
	}{
		{
			name:      "known id should return mapped value",
			idMapping: map[string]string{"old-id": "new-id"},
			original:  "old-id",
			validate: func(t *testing.T, result string) {
				assert.Equal(t, "new-id", result)
			},
		},
		{
			name:      "unknown id should fall back to generated mapping",
			idMapping: map[string]string{},
			original:  "unknown-id",
			validate: func(t *testing.T, result string) {
				assert.NotEqual(t, "unknown-id", result)
				assert.Contains(t, result, "ref-")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mapping := NewMapping()
			result := resolveMappedID(mapping, test.idMapping, test.original, "ref")
			test.validate(t, result)
		})
	}
}

func TestAnonymizeSession_NilSession(t *testing.T) {
	mapping := NewMapping()

	require.NoError(
		t,
		anonymizeSession(nil, mapping, NewMappingTransformer()),
	)
}

func TestAnonymizeSession_NamesAndNamespacesReplaced(t *testing.T) {
	pod := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      "my-secret-pod",
			"namespace": "my-secret-ns",
		},
	})

	oldID := pod.GetID()

	session := &cautils.OPASessionObj{
		AllResources:         map[string]workloadinterface.IMetadata{oldID: pod},
		ResourcesResult:      make(map[string]resourcesresults.Result),
		ResourceSource:       make(map[string]reporthandling.Source),
		ResourcesPrioritized: make(map[string]prioritization.PrioritizedResource),
		ResourceAttackTracks: make(map[string]v1alpha1.IAttackTrack),
	}

	mapping := NewMapping()

	err := anonymizeSession(session, mapping, NewMappingTransformer())
	require.NoError(t, err)

	for _, resource := range session.AllResources {
		assert.NotEqual(t, "my-secret-pod", resource.GetName())
		assert.NotEqual(t, "my-secret-ns", resource.GetNamespace())
		assert.Contains(t, resource.GetName(), "res-")
		assert.Contains(t, resource.GetNamespace(), "ns-")
	}
}

func TestAnonymizeSession_IDConsistencyAcrossMaps(t *testing.T) {
	pod := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      "my-pod",
			"namespace": "default",
		},
	})

	oldID := pod.GetID()

	resourceIDs := helpersv1.AllLists{}
	resourceIDs.Append(apis.StatusFailed, oldID)

	session := &cautils.OPASessionObj{
		AllResources: map[string]workloadinterface.IMetadata{
			oldID: pod,
		},
		ResourcesResult: map[string]resourcesresults.Result{
			oldID: {
				ResourceID: oldID,
				AssociatedControls: []resourcesresults.ResourceAssociatedControl{
					{
						ControlID: "C-0001",
						ResourceAssociatedRules: []resourcesresults.ResourceAssociatedRule{
							{
								Name: "rule-1",
								Paths: []armotypes.PosturePaths{
									{ResourceID: oldID},
								},
								RelatedResourcesIDs: []string{oldID},
							},
						},
					},
				},
			},
		},
		ResourceSource: map[string]reporthandling.Source{
			oldID: {
				Path:             "/home/devjijo/work/acme-platform/manifests/payments/api-deployment.yaml",
				RelativePath:     "clusters/production/payments/api/deployment.yaml",
				HelmPath:         "charts/platform-security",
				FileType:         "Helm Chart",
				HelmChartName:    "payments-service",
				HelmTemplateFile: "templates/api-deployment.yaml",
				HelmValuesPaths: []string{
					"database.connection.url",
					"redis.auth.password",
					"serviceAccount.name",
				},
				HelmTemplateLine:       87,
				KustomizeDirectoryName: "production-overlays",
				LastCommit: reporthandling.LastCommit{
					Hash:           "9f8c7a6b5d4e3f21",
					CommitterName:  "Platform Engineer",
					CommitterEmail: "platform.engineer@example.com",
					Message:        "update deployment configuration",
				},
			},
		},
		ResourcesPrioritized: map[string]prioritization.PrioritizedResource{
			oldID: {ResourceID: oldID},
		},
		ResourceAttackTracks: map[string]v1alpha1.IAttackTrack{
			oldID: &v1alpha1.AttackTrack{},
		},
		Report: &reporthandlingv2.PostureReport{
			SummaryDetails: reportsummary.SummaryDetails{
				Controls: reportsummary.ControlSummaries{
					"C-0001": {
						ResourceIDs: resourceIDs,
					},
				},
			},
		},
	}

	mapping := NewMapping()
	err := anonymizeSession(session, mapping, NewMappingTransformer())
	require.NoError(t, err)

	var newID string
	for id := range session.AllResources {
		newID = id
	}

	assert.NotEmpty(t, newID)
	assert.NotEqual(t, oldID, newID)

	result, ok := session.ResourcesResult[newID]
	assert.True(t, ok)
	assert.Equal(t, newID, result.ResourceID)

	assert.Equal(
		t,
		newID,
		result.AssociatedControls[0].ResourceAssociatedRules[0].Paths[0].ResourceID,
	)

	assert.Equal(
		t,
		newID,
		result.AssociatedControls[0].ResourceAssociatedRules[0].RelatedResourcesIDs[0],
	)

	source, ok := session.ResourceSource[newID]
	assert.True(t, ok)

	assert.NotEqual(
		t,
		"/home/devjijo/work/acme-platform/manifests/payments/api-deployment.yaml",
		source.Path,
	)

	assert.NotEqual(
		t,
		"clusters/production/payments/api/deployment.yaml",
		source.RelativePath,
	)

	assert.NotEqual(
		t,
		"charts/platform-security",
		source.HelmPath,
	)

	assert.NotEqual(
		t,
		"payments-service",
		source.HelmChartName,
	)

	assert.NotEqual(
		t,
		"templates/api-deployment.yaml",
		source.HelmTemplateFile,
	)

	assert.NotEqual(
		t,
		"production-overlays",
		source.KustomizeDirectoryName,
	)

	assert.NotEqual(
		t,
		"database.connection.url",
		source.HelmValuesPaths[0],
	)

	assert.NotEqual(
		t,
		"redis.auth.password",
		source.HelmValuesPaths[1],
	)

	assert.NotEqual(
		t,
		"serviceAccount.name",
		source.HelmValuesPaths[2],
	)

	assert.NotEqual(
		t,
		"9f8c7a6b5d4e3f21",
		source.LastCommit.Hash,
	)

	assert.NotEqual(
		t,
		"Platform Engineer",
		source.LastCommit.CommitterName,
	)

	assert.NotEqual(
		t,
		"platform.engineer@example.com",
		source.LastCommit.CommitterEmail,
	)

	assert.NotEqual(
		t,
		"update deployment configuration",
		source.LastCommit.Message,
	)

	assert.Equal(t, "Helm Chart", source.FileType)
	assert.Equal(t, 87, source.HelmTemplateLine)

	prioritized, ok := session.ResourcesPrioritized[newID]
	assert.True(t, ok)
	assert.Equal(t, newID, prioritized.ResourceID)

	control := session.Report.SummaryDetails.Controls["C-0001"]
	_, found := control.ResourceIDs.All()[newID]
	assert.True(t, found)

	_, ok = session.ResourceAttackTracks[newID]
	assert.True(t, ok)
}

func TestAnonymizeSession_LabelHandling(t *testing.T) {
	tests := []struct {
		name         string
		labelsToCopy []string
		validate     func(t *testing.T, labels map[string]string)
	}{
		{
			name:         "selected labels should be anonymized",
			labelsToCopy: []string{"team", "env"},
			validate: func(t *testing.T, labels map[string]string) {
				assert.NotEqual(t, "payments", labels["team"])
				assert.NotEqual(t, "production", labels["env"])
				assert.Contains(t, labels["team"], "lbl-")
				assert.Contains(t, labels["env"], "lbl-")
			},
		},
		{
			name:         "empty labelsToCopy should preserve labels",
			labelsToCopy: []string{},
			validate: func(t *testing.T, labels map[string]string) {
				assert.Equal(t, "payments", labels["team"])
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pod := workloadinterface.NewWorkloadObj(map[string]any{
				"apiVersion": "v1",
				"kind":       "Pod",
				"metadata": map[string]any{
					"name":      "my-pod",
					"namespace": "default",
					"labels": map[string]any{
						"team": "payments",
						"env":  "production",
					},
				},
			})

			oldID := pod.GetID()

			session := &cautils.OPASessionObj{
				AllResources:         map[string]workloadinterface.IMetadata{oldID: pod},
				ResourcesResult:      make(map[string]resourcesresults.Result),
				ResourceSource:       make(map[string]reporthandling.Source),
				ResourcesPrioritized: make(map[string]prioritization.PrioritizedResource),
				ResourceAttackTracks: make(map[string]v1alpha1.IAttackTrack),
				LabelsToCopy:         test.labelsToCopy,
			}

			mapping := NewMapping()
			err := anonymizeSession(session, mapping, NewMappingTransformer())
			require.NoError(t, err)

			for _, resource := range session.AllResources {
				workload, ok := resource.(workloadinterface.IWorkload)
				assert.True(t, ok)
				test.validate(t, workload.GetLabels())
			}
		})
	}
}

func TestAnonymizeResourceLabels_Guards(t *testing.T) {
	tests := []struct {
		name     string
		resource workloadinterface.IMetadata
	}{
		{
			name:     "non workload resource should be ignored",
			resource: &metadataOnly{},
		},
		{
			name:     "workload without labels should be ignored",
			resource: workloadinterface.NewWorkloadMock(nil),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mapping := NewMapping()

			assert.NotPanics(t, func() {
				anonymizeResourceLabels(test.resource, []string{"team"}, mapping)
			})
		})
	}
}

func TestAnonymizeSession_Annotations(t *testing.T) {
	tests := []struct {
		name     string
		resource map[string]any
		validate func(t *testing.T, resource workloadinterface.IMetadata)
	}{
		{
			name: "annotation values should be anonymized",
			resource: map[string]any{
				"apiVersion": "v1",
				"kind":       "Pod",
				"metadata": map[string]any{
					"name":      "payment-service",
					"namespace": "production",
					"annotations": map[string]any{
						"iam.amazonaws.com/role":                  "arn:aws:iam::ACCOUNT_ID:role/example-role",
						"vault.hashicorp.com/agent-inject-secret": "example/path/config",
					},
				},
			},
			validate: func(t *testing.T, resource workloadinterface.IMetadata) {
				metadata := resource.GetObject()["metadata"].(map[string]any)
				annotations := metadata["annotations"].(map[string]any)

				assert.NotEqual(t, "arn:aws:iam::ACCOUNT_ID:role/example-role", annotations["iam.amazonaws.com/role"])
				assert.NotEqual(t, "example/path/config", annotations["vault.hashicorp.com/agent-inject-secret"])

				assert.Contains(t, annotations["iam.amazonaws.com/role"], "ann-")
				assert.Contains(t, annotations["vault.hashicorp.com/agent-inject-secret"], "ann-")
			},
		},
		{
			name: "nested template annotation values should be anonymized",
			resource: map[string]any{
				"apiVersion": "apps/v1",
				"kind":       "Deployment",
				"metadata": map[string]any{
					"name": "analytics-worker",
				},
				"spec": map[string]any{
					"template": map[string]any{
						"metadata": map[string]any{
							"annotations": map[string]any{
								"secret.company.io/runtime-path": "secret/prod/analytics/runtime",
								"team.company.io/owner":          "analytics-platform",
							},
						},
					},
				},
			},
			validate: func(t *testing.T, resource workloadinterface.IMetadata) {
				spec := resource.GetObject()["spec"].(map[string]any)
				template := spec["template"].(map[string]any)
				metadata := template["metadata"].(map[string]any)
				annotations := metadata["annotations"].(map[string]any)

				assert.NotEqual(
					t,
					"secret/prod/analytics/runtime",
					annotations["secret.company.io/runtime-path"],
				)

				assert.NotEqual(
					t,
					"analytics-platform",
					annotations["team.company.io/owner"],
				)

				assert.Contains(
					t,
					annotations["secret.company.io/runtime-path"],
					"ann-",
				)

				assert.Contains(
					t,
					annotations["team.company.io/owner"],
					"ann-",
				)
			},
		},
		{
			name: "identical annotation values should map deterministically",
			resource: map[string]any{
				"apiVersion": "v1",
				"kind":       "Pod",
				"metadata": map[string]any{
					"annotations": map[string]any{
						"annotation-a": "internal.prod.local",
						"annotation-b": "internal.prod.local",
					},
				},
			},
			validate: func(t *testing.T, resource workloadinterface.IMetadata) {
				metadata := resource.GetObject()["metadata"].(map[string]any)
				annotations := metadata["annotations"].(map[string]any)

				assert.Equal(t, annotations["annotation-a"], annotations["annotation-b"])
			},
		},
		{
			name: "missing metadata should not panic",
			resource: map[string]any{
				"apiVersion": "v1",
				"kind":       "Pod",
			},
			validate: func(t *testing.T, resource workloadinterface.IMetadata) {},
		},
		{
			name: "missing annotations should not panic",
			resource: map[string]any{
				"apiVersion": "v1",
				"kind":       "Pod",
				"metadata": map[string]any{
					"name": "payment",
				},
			},
			validate: func(t *testing.T, resource workloadinterface.IMetadata) {},
		},
		{
			name: "empty annotations should not panic",
			resource: map[string]any{
				"apiVersion": "v1",
				"kind":       "Pod",
				"metadata": map[string]any{
					"annotations": map[string]any{},
				},
			},
			validate: func(t *testing.T, resource workloadinterface.IMetadata) {},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource := workloadinterface.NewWorkloadObj(test.resource)
			oldID := resource.GetID()

			session := &cautils.OPASessionObj{
				AllResources:         map[string]workloadinterface.IMetadata{oldID: resource},
				ResourcesResult:      make(map[string]resourcesresults.Result),
				ResourceSource:       make(map[string]reporthandling.Source),
				ResourcesPrioritized: make(map[string]prioritization.PrioritizedResource),
				ResourceAttackTracks: make(map[string]v1alpha1.IAttackTrack),
			}

			mapping := NewMapping()

			assert.NotPanics(t, func() {
				err := anonymizeSession(session, mapping, NewMappingTransformer())
				require.NoError(t, err)
			})

			for _, resource := range session.AllResources {
				test.validate(t, resource)
			}
		})
	}
}

func TestAnonymizeSession_RepoContextMetadata(t *testing.T) {
	repoContext := &reporthandlingv2.RepoContextMetadata{
		Provider:      "github",
		Repo:          "kubescape",
		Owner:         "jijo-OO7",
		Branch:        "feature/private-work",
		DefaultBranch: "main",
		RemoteURL:     "https://github.com/jijo-OO7/kubescape",
		LocalRootPath: "/home/devjijo/work/kubescape",
		LastCommit: reporthandling.LastCommit{
			Hash:           "abcdef123456",
			CommitterName:  "Platform Engineer",
			CommitterEmail: "platform.engineer@example.com",
			Message:        "internal security fixes",
		},
	}

	session := &cautils.OPASessionObj{
		AllResources:         make(map[string]workloadinterface.IMetadata),
		ResourcesResult:      make(map[string]resourcesresults.Result),
		ResourceSource:       make(map[string]reporthandling.Source),
		ResourcesPrioritized: make(map[string]prioritization.PrioritizedResource),
		ResourceAttackTracks: make(map[string]v1alpha1.IAttackTrack),

		Metadata: &reporthandlingv2.Metadata{
			ContextMetadata: reporthandlingv2.ContextMetadata{
				RepoContextMetadata: &reporthandlingv2.RepoContextMetadata{
					Provider:      repoContext.Provider,
					Repo:          repoContext.Repo,
					Owner:         repoContext.Owner,
					Branch:        repoContext.Branch,
					DefaultBranch: repoContext.DefaultBranch,
					RemoteURL:     repoContext.RemoteURL,
					LocalRootPath: repoContext.LocalRootPath,
					LastCommit:    repoContext.LastCommit,
				},
			},
		},

		Report: &reporthandlingv2.PostureReport{
			Metadata: reporthandlingv2.Metadata{
				ContextMetadata: reporthandlingv2.ContextMetadata{
					RepoContextMetadata: &reporthandlingv2.RepoContextMetadata{
						Provider:      repoContext.Provider,
						Repo:          repoContext.Repo,
						Owner:         repoContext.Owner,
						Branch:        repoContext.Branch,
						DefaultBranch: repoContext.DefaultBranch,
						RemoteURL:     repoContext.RemoteURL,
						LocalRootPath: repoContext.LocalRootPath,
						LastCommit:    repoContext.LastCommit,
					},
				},
			},
		},
	}

	mapping := NewMapping()
	err := anonymizeSession(session, mapping, NewMappingTransformer())
	require.NoError(t, err)

	for _, repo := range []*reporthandlingv2.RepoContextMetadata{
		session.Metadata.ContextMetadata.RepoContextMetadata,
		session.Report.Metadata.ContextMetadata.RepoContextMetadata,
	} {
		assert.NotNil(t, repo)

		if repo == nil {
			return
		}

		assert.Equal(t, "github", repo.Provider)

		assert.NotEqual(t, "kubescape", repo.Repo)
		assert.NotEqual(t, "jijo-OO7", repo.Owner)
		assert.NotEqual(t, "feature/private-work", repo.Branch)
		assert.NotEqual(t, "main", repo.DefaultBranch)
		assert.NotEqual(t, "https://github.com/jijo-OO7/kubescape", repo.RemoteURL)

		assert.NotEqual(
			t,
			"/home/devjijo/work/kubescape",
			repo.LocalRootPath,
		)

		assert.Contains(
			t,
			repo.LocalRootPath,
			"git-",
		)

		assert.Contains(t, repo.Repo, "git-")
		assert.Contains(t, repo.Owner, "git-")
		assert.Contains(t, repo.Branch, "git-")
		assert.Contains(t, repo.DefaultBranch, "git-")
		assert.Contains(t, repo.RemoteURL, "git-")

		assert.NotEqual(t, "abcdef123456", repo.LastCommit.Hash)
		assert.NotEqual(t, "Platform Engineer", repo.LastCommit.CommitterName)
		assert.NotEqual(t, "platform.engineer@example.com", repo.LastCommit.CommitterEmail)
		assert.NotEqual(t, "internal security fixes", repo.LastCommit.Message)

		assert.Contains(t, repo.LastCommit.Hash, "git-")
		assert.Contains(t, repo.LastCommit.CommitterName, "git-")
		assert.Contains(t, repo.LastCommit.CommitterEmail, "git-")
		assert.Contains(t, repo.LastCommit.Message, "git-")
	}
}

func TestTransformRepoContextMetadata(t *testing.T) {
	repo := &reporthandlingv2.RepoContextMetadata{
		Provider:      "github",
		Repo:          "demo-repository",
		Owner:         "demo-owner",
		Branch:        "feature/demo-work",
		DefaultBranch: "main",
		RemoteURL:     "https://github.com/demo-owner/demo-repository",
		LocalRootPath: "/workspace/demo-repository",
		LastCommit: reporthandling.LastCommit{
			Hash:           "demo-commit-hash",
			CommitterName:  "Demo User",
			CommitterEmail: "demo@example.com",
			Message:        "demo commit message",
		},
	}

	err := transformRepoContextMetadata(
		repo,
		NewMappingTransformer(),
	)
	require.NoError(t, err)

	assert.NotEqual(t, "demo-repository", repo.Repo)
	assert.NotEqual(t, "demo-owner", repo.Owner)
	assert.NotEqual(t, "feature/demo-work", repo.Branch)
	assert.NotEqual(t, "main", repo.DefaultBranch)
	assert.NotEqual(t, "https://github.com/demo-owner/demo-repository", repo.RemoteURL)
	assert.NotEqual(t, "/workspace/demo-repository", repo.LocalRootPath)

	assert.Contains(t, repo.Repo, "git-")
	assert.Contains(t, repo.Owner, "git-")
	assert.Contains(t, repo.Branch, "git-")
	assert.Contains(t, repo.DefaultBranch, "git-")
	assert.Contains(t, repo.RemoteURL, "git-")
	assert.Contains(t, repo.LocalRootPath, "git-")

	assert.NotEqual(t, "demo-commit-hash", repo.LastCommit.Hash)
	assert.NotEqual(t, "Demo User", repo.LastCommit.CommitterName)
	assert.NotEqual(t, "demo@example.com", repo.LastCommit.CommitterEmail)
	assert.NotEqual(t, "demo commit message", repo.LastCommit.Message)

	assert.Contains(t, repo.LastCommit.Hash, "git-")
	assert.Contains(t, repo.LastCommit.CommitterName, "git-")
	assert.Contains(t, repo.LastCommit.CommitterEmail, "git-")
	assert.Contains(t, repo.LastCommit.Message, "git-")
}

func TestTransformRepoContextMetadata_EncryptionTransformer(
	t *testing.T,
) {
	dek, err := reportcrypto.GenerateDEK()
	require.NoError(t, err)

	transformer := NewEncryptionTransformer(dek)

	repo := &reporthandlingv2.RepoContextMetadata{
		Provider:      "github",
		Repo:          "demo-repository",
		Owner:         "demo-owner",
		Branch:        "feature/demo-work",
		DefaultBranch: "main",
		RemoteURL:     "https://github.com/demo-owner/demo-repository",
		LocalRootPath: "/workspace/demo-repository",
		LastCommit: reporthandling.LastCommit{
			Hash:           "demo-commit-hash",
			CommitterName:  "Demo User",
			CommitterEmail: "demo@example.com",
			Message:        "demo commit message",
		},
	}

	err = transformRepoContextMetadata(
		repo,
		transformer,
	)
	require.NoError(t, err)

	assert.Contains(t, repo.Repo, "ENC[AES256_GCM,")
	assert.Contains(t, repo.Owner, "ENC[AES256_GCM,")
	assert.Contains(t, repo.Branch, "ENC[AES256_GCM,")
	assert.Contains(t, repo.DefaultBranch, "ENC[AES256_GCM,")
	assert.Contains(t, repo.RemoteURL, "ENC[AES256_GCM,")
	assert.Contains(t, repo.LocalRootPath, "ENC[AES256_GCM,")

	assert.Contains(t, repo.LastCommit.Hash, "ENC[AES256_GCM,")
	assert.Contains(t, repo.LastCommit.CommitterName, "ENC[AES256_GCM,")
	assert.Contains(t, repo.LastCommit.CommitterEmail, "ENC[AES256_GCM,")
	assert.Contains(t, repo.LastCommit.Message, "ENC[AES256_GCM,")

	decryptedRepo, err := reportcrypto.DecryptString(
		repo.Repo,
		dek,
	)
	require.NoError(t, err)

	assert.Equal(
		t,
		"demo-repository",
		decryptedRepo,
	)
}

func TestTransformRepoContextMetadata_Error(
	t *testing.T,
) {
	repo := &reporthandlingv2.RepoContextMetadata{
		Repo:          "demo-repository",
		Owner:         "demo-owner",
		Branch:        "feature/demo-work",
		DefaultBranch: "main",
		RemoteURL:     "https://github.com/demo-owner/demo-repository",
		LocalRootPath: "/workspace/demo-repository",
	}

	err := transformRepoContextMetadata(
		repo,
		&failingTransformer{},
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "transform failed")
	assert.Equal(t, "demo-repository", repo.Repo)
	assert.Equal(t, "demo-owner", repo.Owner)
	assert.Equal(t, "feature/demo-work", repo.Branch)
	assert.Equal(t, "main", repo.DefaultBranch)
	assert.Equal(
		t,
		"https://github.com/demo-owner/demo-repository",
		repo.RemoteURL,
	)
	assert.Equal(
		t,
		"/workspace/demo-repository",
		repo.LocalRootPath,
	)
}

func TestTransformResourceSource(t *testing.T) {
	source := &reporthandling.Source{
		Path:             "/workspace/private/app.yaml",
		RelativePath:     "services/payments/app.yaml",
		HelmPath:         "charts/internal",
		HelmChartName:    "payments-service",
		HelmTemplateFile: "templates/deployment.yaml",
		HelmValuesPaths: []string{
			"database.password",
			"redis.password",
		},
		KustomizeDirectoryName: "prod-overlay",
		LastCommit: reporthandling.LastCommit{
			Hash:           "abc123",
			CommitterName:  "John Doe",
			CommitterEmail: "john@example.com",
			Message:        "internal change",
		},
	}

	err := transformResourceSource(
		source,
		NewMappingTransformer(),
	)
	require.NoError(t, err)

	assert.Contains(t, source.Path, "src-")
	assert.Contains(t, source.RelativePath, "src-")
	assert.Contains(t, source.HelmPath, "src-")
	assert.Contains(t, source.HelmChartName, "src-")
	assert.Contains(t, source.HelmTemplateFile, "src-")
	assert.Contains(t, source.KustomizeDirectoryName, "src-")

	assert.Contains(t, source.LastCommit.Hash, "git-")
	assert.Contains(t, source.LastCommit.CommitterName, "git-")
	assert.Contains(t, source.LastCommit.CommitterEmail, "git-")
	assert.Contains(t, source.LastCommit.Message, "git-")

	assert.Len(t, source.HelmValuesPaths, 2)

	assert.Contains(t, source.HelmValuesPaths[0], "src-")
	assert.Contains(t, source.HelmValuesPaths[1], "src-")

	assert.NotEqual(t, "database.password", source.HelmValuesPaths[0])
	assert.NotEqual(t, "redis.password", source.HelmValuesPaths[1])
}

func TestTransformResourceSource_EncryptionTransformer(
	t *testing.T,
) {
	dek, err := reportcrypto.GenerateDEK()
	require.NoError(t, err)

	transformer := NewEncryptionTransformer(dek)

	source := &reporthandling.Source{
		Path: "/workspace/private/app.yaml",
		LastCommit: reporthandling.LastCommit{
			Hash: "abc123",
		},
	}

	err = transformResourceSource(
		source,
		transformer,
	)
	require.NoError(t, err)

	assert.Contains(t, source.Path, "ENC[AES256_GCM,")
	assert.Contains(t, source.LastCommit.Hash, "ENC[AES256_GCM,")

	decrypted, err := reportcrypto.DecryptString(
		source.Path,
		dek,
	)

	require.NoError(t, err)

	assert.Equal(
		t,
		"/workspace/private/app.yaml",
		decrypted,
	)
}

func TestTransformResourceSource_Error(
	t *testing.T,
) {
	source := &reporthandling.Source{
		Path: "/workspace/private/app.yaml",
	}

	err := transformResourceSource(
		source,
		&failingTransformer{},
	)

	require.Error(t, err)

	assert.Equal(t, "/workspace/private/app.yaml", source.Path)
}

func TestAnonymizeSession_ResourceSourceEncryption(
	t *testing.T,
) {
	dek, err := reportcrypto.GenerateDEK()
	require.NoError(t, err)

	pod := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      "payment-api",
			"namespace": "production",
		},
	})

	oldID := pod.GetID()

	session := &cautils.OPASessionObj{
		AllResources: map[string]workloadinterface.IMetadata{
			oldID: pod,
		},

		ResourceSource: map[string]reporthandling.Source{
			oldID: {
				Path:         "/workspace/private/app.yaml",
				RelativePath: "services/payments/app.yaml",
				LastCommit: reporthandling.LastCommit{
					Hash:           "abc123",
					CommitterName:  "John Doe",
					CommitterEmail: "john@example.com",
					Message:        "internal change",
				},
			},
		},

		ResourcesResult:      make(map[string]resourcesresults.Result),
		ResourcesPrioritized: make(map[string]prioritization.PrioritizedResource),
		ResourceAttackTracks: make(map[string]v1alpha1.IAttackTrack),
	}

	err = anonymizeSession(
		session,
		NewMapping(),
		NewEncryptionTransformer(dek),
	)
	require.NoError(t, err)

	var source reporthandling.Source

	for _, s := range session.ResourceSource {
		source = s
		break
	}

	assert.Contains(t, source.Path, "ENC[AES256_GCM,")
	assert.Contains(t, source.RelativePath, "ENC[AES256_GCM,")
	assert.Contains(t, source.LastCommit.Hash, "ENC[AES256_GCM,")

	decryptedPath, err := reportcrypto.DecryptString(
		source.Path,
		dek,
	)
	require.NoError(t, err)

	assert.Equal(t, "/workspace/private/app.yaml", decryptedPath)

	decryptedHash, err := reportcrypto.DecryptString(
		source.LastCommit.Hash,
		dek,
	)
	require.NoError(t, err)

	assert.Equal(t, "abc123", decryptedHash)
}

func TestTransformResourceMetadata_EncryptionTransformer(
	t *testing.T,
) {
	dek, err := reportcrypto.GenerateDEK()
	require.NoError(t, err)

	transformer := NewEncryptionTransformer(dek)

	resource := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      "payment-api",
			"namespace": "production",
		},
	})

	err = transformResourceMetadata(
		resource,
		transformer,
	)
	require.NoError(t, err)

	assert.Contains(
		t,
		resource.GetName(),
		"ENC[AES256_GCM,",
	)

	assert.Contains(
		t,
		resource.GetNamespace(),
		"ENC[AES256_GCM,",
	)

	decryptedName, err := reportcrypto.DecryptString(
		resource.GetName(),
		dek,
	)
	require.NoError(t, err)

	assert.Equal(
		t,
		"payment-api",
		decryptedName,
	)

	decryptedNamespace, err := reportcrypto.DecryptString(
		resource.GetNamespace(),
		dek,
	)
	require.NoError(t, err)

	assert.Equal(
		t,
		"production",
		decryptedNamespace,
	)
}

func TestTransformResourceMetadata_Error(
	t *testing.T,
) {
	resource := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      "payment-api",
			"namespace": "production",
		},
	})

	err := transformResourceMetadata(
		resource,
		&failingTransformer{},
	)

	require.Error(t, err)

	assert.Equal(
		t,
		"payment-api",
		resource.GetName(),
	)

	assert.Equal(
		t,
		"production",
		resource.GetNamespace(),
	)
}
