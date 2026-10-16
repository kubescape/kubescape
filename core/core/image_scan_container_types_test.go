package core

import (
	"context"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/pkg/imagescan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

const (
	containerTypesRegularImage   = "alpine:3.20"
	containerTypesInitImage      = "busybox:1.36"
	containerTypesEphemeralImage = "ubuntu:24.04"
)

type containerTypesPodSpec struct {
	name       string
	namespace  string
	pullSecret string
	regular    []string
	init       []string
	ephemeral  []string
}

func containerTypesList(prefix string, images []string) []interface{} {
	list := make([]interface{}, 0, len(images))
	for i, image := range images {
		list = append(list, map[string]interface{}{
			"name":  prefix + string(rune('a'+i)),
			"image": image,
		})
	}
	return list
}

func newContainerTypesPod(p containerTypesPodSpec) *workloadinterface.Workload {
	if p.namespace == "" {
		p.namespace = "default"
	}
	spec := map[string]interface{}{}
	if len(p.regular) > 0 {
		spec["containers"] = containerTypesList("c", p.regular)
	}
	if len(p.init) > 0 {
		spec["initContainers"] = containerTypesList("i", p.init)
	}
	if len(p.ephemeral) > 0 {
		spec["ephemeralContainers"] = containerTypesList("e", p.ephemeral)
	}
	if p.pullSecret != "" {
		spec["imagePullSecrets"] = []interface{}{map[string]interface{}{"name": p.pullSecret}}
	}
	return workloadinterface.NewWorkloadObj(map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name":      p.name,
			"namespace": p.namespace,
		},
		"spec": spec,
	})
}

func newContainerTypesSecret(name, auths string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data:       map[string][]byte{corev1.DockerConfigJsonKey: []byte(`{"auths":{` + auths + `}}`)},
	}
}

// collectContainerTypesTargets runs collectImageScanTargets over the given pods
// through either the single-workload path or the all-resources path.
func collectContainerTypesTargets(t *testing.T, singleWorkload bool, scanningContext cautils.ScanningContext, k8sAPI *k8sinterface.KubernetesApi, pods ...*workloadinterface.Workload) ([]ImageScanTarget, map[string][]imagescan.RegistryCredentials, []error) {
	t.Helper()
	scanData := cautils.NewOPASessionObjMock()
	scanType := cautils.ScanTypeCluster
	if singleWorkload {
		require.Len(t, pods, 1, "the single-workload path scans exactly one resource")
		scanType = cautils.ScanTypeWorkload
		scanData.SingleResourceScan = pods[0]
	} else {
		for _, pod := range pods {
			scanData.AllResources[pod.GetID()] = pod
		}
	}
	targets, creds, errs := collectImageScanTargets(scanType, scanData, context.Background(), scanningContext, k8sAPI, "")
	return targets.ToSlice(), creds, errs
}

func TestCollectImageScanTargetsIncludesAllContainerTypes(t *testing.T) {
	for _, singleWorkload := range []bool{true, false} {
		name := "all resources"
		if singleWorkload {
			name = "single workload"
		}
		t.Run(name, func(t *testing.T) {
			pod := newContainerTypesPod(containerTypesPodSpec{
				name:      "all-container-types",
				regular:   []string{containerTypesRegularImage},
				init:      []string{containerTypesInitImage},
				ephemeral: []string{containerTypesEphemeralImage},
			})

			targets, creds, errs := collectContainerTypesTargets(t, singleWorkload, cautils.ContextFile, nil, pod)

			assert.Empty(t, errs)
			assert.Empty(t, creds)
			assert.ElementsMatch(t, []ImageScanTarget{
				{Image: containerTypesRegularImage},
				{Image: containerTypesInitImage},
				{Image: containerTypesEphemeralImage},
			}, targets)
		})
	}
}

func TestCollectImageScanTargetsDeduplicatesImagesAcrossContainerTypes(t *testing.T) {
	tests := []struct {
		name string
		pods []*workloadinterface.Workload
		want []ImageScanTarget
	}{
		{
			name: "regular and init container share an image",
			pods: []*workloadinterface.Workload{newContainerTypesPod(containerTypesPodSpec{
				name:    "shared",
				regular: []string{containerTypesRegularImage},
				init:    []string{containerTypesRegularImage},
			})},
			want: []ImageScanTarget{{Image: containerTypesRegularImage}},
		},
		{
			name: "multiple containers of one workload share an image",
			pods: []*workloadinterface.Workload{newContainerTypesPod(containerTypesPodSpec{
				name:      "repeated",
				regular:   []string{containerTypesRegularImage, containerTypesRegularImage},
				init:      []string{containerTypesInitImage, containerTypesInitImage},
				ephemeral: []string{containerTypesEphemeralImage, containerTypesEphemeralImage},
			})},
			want: []ImageScanTarget{
				{Image: containerTypesRegularImage},
				{Image: containerTypesInitImage},
				{Image: containerTypesEphemeralImage},
			},
		},
		{
			name: "two workloads share images across container types",
			pods: []*workloadinterface.Workload{
				newContainerTypesPod(containerTypesPodSpec{
					name:    "first",
					regular: []string{containerTypesRegularImage},
					init:    []string{containerTypesInitImage},
				}),
				newContainerTypesPod(containerTypesPodSpec{
					name:      "second",
					regular:   []string{containerTypesInitImage},
					init:      []string{containerTypesRegularImage},
					ephemeral: []string{containerTypesEphemeralImage},
				}),
			},
			want: []ImageScanTarget{
				{Image: containerTypesRegularImage},
				{Image: containerTypesInitImage},
				{Image: containerTypesEphemeralImage},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targets, _, errs := collectContainerTypesTargets(t, false, cautils.ContextFile, nil, tt.pods...)

			assert.Empty(t, errs)
			assert.ElementsMatch(t, tt.want, targets)
		})
	}
}

func TestCollectImageScanTargetsResolvesPullSecretsForEveryContainerType(t *testing.T) {
	const (
		regularImage   = "reg-a.example.com/team/app:1"
		initImage      = "reg-b.example.com/team/init:1"
		ephemeralImage = "reg-c.example.com/team/debug:1"
		unmatchedImage = "reg-d.example.com/team/other:1"
	)
	credsFor := func(authority, user string) imagescan.RegistryCredentials {
		return imagescan.RegistryCredentials{Authority: authority, Username: user, Password: "pw"}
	}

	t.Run("single workload", func(t *testing.T) {
		client := fake.NewClientset(newContainerTypesSecret("pull",
			`"reg-a.example.com":{"username":"user-a","password":"pw"},`+
				`"reg-b.example.com":{"username":"user-b","password":"pw"},`+
				`"reg-c.example.com":{"username":"user-c","password":"pw"}`))
		pod := newContainerTypesPod(containerTypesPodSpec{
			name:       "app",
			pullSecret: "pull",
			regular:    []string{regularImage},
			init:       []string{initImage},
			ephemeral:  []string{ephemeralImage, unmatchedImage},
		})

		targets, creds, errs := collectContainerTypesTargets(t, true, cautils.ContextCluster,
			&k8sinterface.KubernetesApi{KubernetesClient: client}, pod)

		assert.Empty(t, errs)
		assert.ElementsMatch(t, []ImageScanTarget{
			{Image: regularImage}, {Image: initImage}, {Image: ephemeralImage}, {Image: unmatchedImage},
		}, targets)
		// Each image receives the credential of its own registry, whichever
		// container type references it; an image with no matching entry gets none.
		assert.Equal(t, map[string][]imagescan.RegistryCredentials{
			regularImage:   {credsFor("reg-a.example.com", "user-a")},
			initImage:      {credsFor("reg-b.example.com", "user-b")},
			ephemeralImage: {credsFor("reg-c.example.com", "user-c")},
		}, creds)
	})

	t.Run("all resources merges credentials per image", func(t *testing.T) {
		client := fake.NewClientset(
			newContainerTypesSecret("pull-one", `"reg-a.example.com":{"username":"user-a1","password":"pw"}`),
			newContainerTypesSecret("pull-two", `"reg-a.example.com":{"username":"user-a2","password":"pw"}`),
			newContainerTypesSecret("pull-dup", `"reg-a.example.com":{"username":"user-a1","password":"pw"}`),
		)
		// All three workloads reference regularImage, each through a different
		// container type and a different pull secret.
		one := newContainerTypesPod(containerTypesPodSpec{name: "one", pullSecret: "pull-one", regular: []string{regularImage}})
		two := newContainerTypesPod(containerTypesPodSpec{name: "two", pullSecret: "pull-two", init: []string{regularImage}})
		dup := newContainerTypesPod(containerTypesPodSpec{name: "dup", pullSecret: "pull-dup", ephemeral: []string{regularImage}})

		targets, creds, errs := collectContainerTypesTargets(t, false, cautils.ContextCluster,
			&k8sinterface.KubernetesApi{KubernetesClient: client}, one, two, dup)

		assert.Empty(t, errs)
		assert.Equal(t, []ImageScanTarget{{Image: regularImage}}, targets)
		// Distinct credentials are all kept; an identical credential coming from
		// a second workload is not repeated.
		require.Len(t, creds, 1)
		assert.ElementsMatch(t, []imagescan.RegistryCredentials{
			credsFor("reg-a.example.com", "user-a1"),
			credsFor("reg-a.example.com", "user-a2"),
		}, creds[regularImage])
	})

	t.Run("workload without pull secrets resolves nothing", func(t *testing.T) {
		client := fake.NewClientset(newContainerTypesSecret("pull", `"reg-a.example.com":{"username":"user-a","password":"pw"}`))
		pod := newContainerTypesPod(containerTypesPodSpec{
			name:      "no-secrets",
			regular:   []string{regularImage},
			init:      []string{initImage},
			ephemeral: []string{ephemeralImage},
		})

		_, creds, errs := collectContainerTypesTargets(t, false, cautils.ContextCluster,
			&k8sinterface.KubernetesApi{KubernetesClient: client}, pod)

		assert.Empty(t, errs)
		assert.Empty(t, creds)
		assert.Empty(t, client.Actions())
	})
}

func TestCollectImageScanTargetsDoesNotReadSecretsOutsideClusterContext(t *testing.T) {
	const image = "reg-a.example.com/team/app:1"
	contexts := map[string]cautils.ScanningContext{
		"file":       cautils.ContextFile,
		"directory":  cautils.ContextDir,
		"git local":  cautils.ContextGitLocal,
		"git remote": cautils.ContextGitRemote,
	}

	for contextName, scanningContext := range contexts {
		for _, singleWorkload := range []bool{true, false} {
			name := contextName + "/all resources"
			if singleWorkload {
				name = contextName + "/single workload"
			}
			t.Run(name, func(t *testing.T) {
				client := fake.NewClientset(newContainerTypesSecret("pull", `"reg-a.example.com":{"username":"user-a","password":"pw"}`))
				pod := newContainerTypesPod(containerTypesPodSpec{
					name:       "app",
					pullSecret: "pull",
					regular:    []string{image},
					init:       []string{"reg-a.example.com/team/init:1"},
					ephemeral:  []string{"reg-a.example.com/team/debug:1"},
				})

				targets, creds, errs := collectContainerTypesTargets(t, singleWorkload, scanningContext,
					&k8sinterface.KubernetesApi{KubernetesClient: client}, pod)

				assert.Empty(t, errs)
				assert.Len(t, targets, 3)
				assert.Empty(t, creds)
				assert.Empty(t, client.Actions(), "offline image scans must not read imagePullSecrets from the current cluster")
			})
		}
	}
}
