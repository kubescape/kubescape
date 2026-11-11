package opaprocessor

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

// fake is concatenated into fixtures so the test source holds no
// credential-shaped literals for secret scanners to flag.
const fake = "fake"

func TestRedactArg(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"--db-password=" + fake, "--db-password=XXXXXX"},
		{"--password=" + fake + " beta", "--password=XXXXXX"},
		{"--api-key=" + fake, "--api-key=XXXXXX"},
		{"export AWS_SECRET_ACCESS_KEY=" + fake + " && ./run", "export AWS_SECRET_ACCESS_KEY=XXXXXX && ./run"},
		{`export TOKEN="` + fake + ` b" && ./run`, "export TOKEN=XXXXXX && ./run"},
		{`export TOKEN="` + fake + `\" b" && ./run`, "export TOKEN=XXXXXX && ./run"},
		{"exec server --password " + fake + " --port 80", "exec server --password XXXXXX --port 80"},
		{`exec server --password "` + fake + ` 2"`, "exec server --password XXXXXX"},
		{"_API_TOKEN=" + fake, "_API_TOKEN=XXXXXX"},
		{"export _API_TOKEN=" + fake + " && ./run", "export _API_TOKEN=XXXXXX && ./run"},
		{"echo ok;API_TOKEN=" + fake, "echo ok;API_TOKEN=XXXXXX"},
		{"ok;API_TOKEN=" + fake, "ok;API_TOKEN=XXXXXX"},
		{"true&&API_TOKEN=" + fake + "|cat", "true&&API_TOKEN=XXXXXX|cat"},
		{`echo "a;b" 'c|d' && TOKEN=` + fake, `echo "a;b" 'c|d' && TOKEN=XXXXXX`},
		{"--redis-url=redis://:" + fake + "@redis:6379/0", "--redis-url=redis://:XXXXXX@redis:6379/0"},
		{"redis://:" + fake + "@redis:6379/0", "redis://:XXXXXX@redis:6379/0"},
		{"https://example.com/a?x=1&y=2", "https://example.com/a?x=1&y=2"},
		{"API_TOKEN=" + fake + " beta", "API_TOKEN=XXXXXX"},
		{"DB_HOST=db PASSWORD=" + fake, "DB_HOST=db PASSWORD=XXXXXX"},
		{"sh -c 'export TOKEN=" + fake + " && ./run'", "sh -c 'export TOKEN=XXXXXX && ./run'"},
		{`bash -c "curl -H 'Authorization: Bearer ` + fake + `' https://api"`, `bash -c "curl -H 'Authorization: XXXXXX' https://api"`},
		{"sh -c 'TOKEN=" + fake + " && /usr/bin/server --port 80'", "sh -c 'TOKEN=XXXXXX && /usr/bin/server --port 80'"},
		{"curl -H 'X_API_KEY: " + fake + "' https://api", "curl -H 'X_API_KEY: XXXXXX' https://api"},
		{"X_API_KEY: " + fake, "X_API_KEY: XXXXXX"},
		{"mongodb+srv://user:p&" + fake + "@host/db", "mongodb+srv://user:XXXXXX@host/db"},
		{"--mongo-uri=mongodb+srv://user:p&" + fake + "@host/db", "--mongo-uri=mongodb+srv://user:XXXXXX@host/db"},
		{"./run --db mongodb://user:p;" + fake + "|x@host/db && echo ok", "./run --db mongodb://user:XXXXXX@host/db && echo ok"},
		{`sh -c "server --password '-` + fake + `'"`, `sh -c "server --password XXXXXX"`},
		{`server --password "-` + fake + `" --port 80`, "server --password XXXXXX --port 80"},
		{"server --password --port 80", "server --password --port 80"},
		{`server --token 'true'`, `server --token 'true'`},
		{"Authorization: Bearer " + fake, "Authorization: XXXXXX"},
		{"X-Api-Key: " + fake, "X-Api-Key: XXXXXX"},
		{"--header=Authorization: Basic " + fake, "--header=Authorization: XXXXXX"},
		{`curl -H "Authorization: Bearer ` + fake + `" https://api`, `curl -H "Authorization: XXXXXX" https://api`},
		{"--db-url=postgres://app:" + fake + "@db:5432/app", "--db-url=postgres://app:XXXXXX@db:5432/app"},
		{"postgres://app:" + fake + "@" + fake + "@db/app", "postgres://app:XXXXXX@db/app"},
		{"https://example.com:8443/path?a=b@c", "https://example.com:8443/path?a=b@c"},
		{"--token-auth-file=/etc/tokens.csv", "--token-auth-file=/etc/tokens.csv"},
		{"--service-account-private-key-file=/k.pem", "--service-account-private-key-file=/k.pem"},
		{"--tls-secret-name=ingress-tls", "--tls-secret-name=ingress-tls"},
		{"--enable-bootstrap-token-auth=true", "--enable-bootstrap-token-auth=true"},
		{"--anonymous-auth=false", "--anonymous-auth=false"},
		{"--port=8080", "--port=8080"},
		{"--password=", "--password="},
		{"Accept: application/json", "Accept: application/json"},
		{"echo hello world", "echo hello world"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, redactArg(tc.in))
		})
	}
}

func TestRedactCommandLine(t *testing.T) {
	argv := []string{"server", "--password", fake, "--secret", "--verbose", "--port", "80", "--token=" + fake, "--enable-token-auth", "true"}
	redactCommandLine(argv)
	assert.Equal(t, []string{"server", "--password", "XXXXXX", "--secret", "--verbose", "--port", "80", "--token=XXXXXX", "--enable-token-auth", "true"}, argv)
}

func TestRedactCommandLine_FlagValueSpansCommandAndArgs(t *testing.T) {
	command := []string{"server", "--password"}
	args := []string{fake, "--port", "80"}
	redactCommandLine(command, args)
	assert.Equal(t, []string{"server", "--password"}, command)
	assert.Equal(t, []string{"XXXXXX", "--port", "80"}, args)
}

func TestRedactArg_EscapedSeparatorDoesNotLeak(t *testing.T) {
	got := redactArg(`echo e\;TOKEN=` + fake)
	assert.NotContains(t, got, fake)
}

func TestRedactCommandLine_ScriptStartingWithAssignment(t *testing.T) {
	command := []string{"/bin/sh", "-ec"}
	args := []string{"TOKEN=" + fake + " && /usr/bin/server --port 80"}
	redactCommandLine(command, args)
	assert.Equal(t, []string{"TOKEN=XXXXXX && /usr/bin/server --port 80"}, args)

	direct := []string{"/usr/bin/server", "API_TOKEN=" + fake + " beta"}
	redactCommandLine(direct)
	assert.Equal(t, []string{"/usr/bin/server", "API_TOKEN=XXXXXX"}, direct)
}

func TestIsScriptFlag(t *testing.T) {
	for _, word := range []string{"-c", "-ec", "-lc", "-xec"} {
		assert.True(t, isScriptFlag(word), word)
	}
	for _, word := range []string{"c", "-", "--c", "--exec", "-Dfoo=abc", "-C", "-cx"} {
		assert.False(t, isScriptFlag(word), word)
	}
}

func TestRedactCommandLine_NestedScript(t *testing.T) {
	argv := []string{"sh", "-c", "su app -c 'export TOKEN=" + fake + " && ./run'"}
	redactCommandLine(argv)
	assert.Equal(t, []string{"sh", "-c", "su app -c 'export TOKEN=XXXXXX && ./run'"}, argv)
}

func TestRedactCommandLine_CurlHeader(t *testing.T) {
	argv := []string{"curl", "-H", "Authorization: Bearer " + fake, "-H", "X_API_KEY: " + fake, "--header", "Accept: text/plain", "https://api"}
	redactCommandLine(argv)
	assert.Equal(t, []string{"curl", "-H", "Authorization: XXXXXX", "-H", "X_API_KEY: XXXXXX", "--header", "Accept: text/plain", "https://api"}, argv)
}

func TestRemoveData_RedactsSecretsOutsideEnv(t *testing.T) {
	obj := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name": "app",
			"annotations": map[string]any{
				"vault.example.com/token":              fake,
				"example.com/owner":                    "team-a",
				"vault.example.com/agent-inject-token": "true",
			},
		},
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{
					"annotations": map[string]any{"db-password": fake},
				},
				"spec": map[string]any{
					"containers": []any{map[string]any{
						"name":    "app",
						"image":   "app:1",
						"command": []any{"server", "--password"},
						"args":    []any{fake, "--db-password=" + fake, "--anonymous-auth=false"},
						"livenessProbe": map[string]any{
							"httpGet": map[string]any{
								"path": "/healthz",
								"port": 8080,
								"httpHeaders": []any{
									map[string]any{"name": "Authorization", "value": "Bearer " + fake},
									map[string]any{"name": "Accept", "value": "application/json"},
								},
							},
						},
						"lifecycle": map[string]any{
							"preStop": map[string]any{
								"exec": map[string]any{"command": []any{"curl", "--token", fake}},
							},
							"postStart": map[string]any{
								"exec": map[string]any{"command": []any{"sh", "-c", "export API_TOKEN=" + fake + " && ./run"}},
							},
						},
					}},
				},
			},
		},
	}
	w := workloadinterface.NewWorkloadObj(obj)
	removeData(w)

	assert.Equal(t, "XXXXXX", w.GetAnnotations()["vault.example.com/token"])
	assert.Equal(t, "team-a", w.GetAnnotations()["example.com/owner"])
	assert.Equal(t, "true", w.GetAnnotations()["vault.example.com/agent-inject-token"])
	templateAnnotations, ok := workloadinterface.InspectMap(w.GetObject(), "spec", "template", "metadata", "annotations")
	require.True(t, ok)
	assert.Equal(t, "XXXXXX", templateAnnotations.(map[string]any)["db-password"])

	containers, err := w.GetContainers()
	require.NoError(t, err)
	require.Len(t, containers, 1)
	c := containers[0]
	assert.Equal(t, []string{"server", "--password"}, c.Command)
	assert.Equal(t, []string{"XXXXXX", "--db-password=XXXXXX", "--anonymous-auth=false"}, c.Args)
	assert.Equal(t, []string{"sh", "-c", "export API_TOKEN=XXXXXX && ./run"}, c.Lifecycle.PostStart.Exec.Command)
	assert.Equal(t, []corev1.HTTPHeader{
		{Name: "Authorization", Value: "XXXXXX"},
		{Name: "Accept", Value: "application/json"},
	}, c.LivenessProbe.HTTPGet.HTTPHeaders)
	assert.Equal(t, []string{"curl", "--token", "XXXXXX"}, c.Lifecycle.PreStop.Exec.Command)
}

func TestRemoveEphemeralContainersData_RedactsArgs(t *testing.T) {
	containers := []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{
		Name: "debug",
		Args: []string{"--password=" + fake},
	}}}
	removeEphemeralContainersData(containers)
	assert.Equal(t, []string{"--password=XXXXXX"}, containers[0].Args)
}
