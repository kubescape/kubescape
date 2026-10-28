package pss

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseLocalWorkloadsFromReader_MatchesAPIGroup(t *testing.T) {
	for _, tc := range []struct {
		name     string
		manifest string
		want     []string
	}{
		{
			name: "built-in workloads in their own groups",
			manifest: `apiVersion: v1
kind: Pod
metadata:
  name: pod
spec:
  containers:
  - name: app
    image: nginx
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: deployment
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx
---
apiVersion: batch/v1
kind: Job
metadata:
  name: job
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx
`,
			want: []string{"Pod/pod", "Deployment/deployment", "Job/job"},
		},
		{
			name: "custom resources reusing workload kind names",
			manifest: `apiVersion: batch.volcano.sh/v1alpha1
kind: Job
metadata:
  name: volcano-job
spec:
  tasks:
  - name: worker
    replicas: 2
    template:
      spec:
        containers:
        - name: app
          image: nginx
---
apiVersion: apps.kruise.io/v1beta1
kind: StatefulSet
metadata:
  name: kruise-sts
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx
---
apiVersion: example.com/v1
kind: Pod
metadata:
  name: custom-pod
spec:
  containers:
  - name: app
    image: nginx
`,
		},
		{
			name: "typed list of custom resources",
			manifest: `apiVersion: batch.volcano.sh/v1alpha1
kind: JobList
items:
- metadata:
    name: volcano-job
  spec:
    tasks:
    - name: worker
      template:
        spec:
          containers:
          - name: app
            image: nginx
`,
		},
		{
			name: "generic list mixing built-in and custom groups",
			manifest: `apiVersion: v1
kind: List
items:
- apiVersion: batch/v1
  kind: Job
  metadata:
    name: job
  spec:
    template:
      spec:
        containers:
        - name: app
          image: nginx
- apiVersion: batch.volcano.sh/v1alpha1
  kind: Job
  metadata:
    name: volcano-job
  spec:
    tasks: []
`,
			want: []string{"Job/job"},
		},
		{
			name: "manifest without apiVersion is matched by kind",
			manifest: `kind: Deployment
metadata:
  name: deployment
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx
`,
			want: []string{"Deployment/deployment"},
		},
		{
			name: "manifest with an unparseable apiVersion is matched by kind",
			manifest: `apiVersion: apps/v1/extra
kind: Deployment
metadata:
  name: deployment
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx
`,
			want: []string{"Deployment/deployment"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objs, err := ParseLocalWorkloadsFromReader(strings.NewReader(tc.manifest), "test")
			require.NoError(t, err)
			var got []string
			for _, obj := range objs {
				got = append(got, obj.GetKind()+"/"+obj.GetName())
			}
			require.Equal(t, tc.want, got)
		})
	}
}
