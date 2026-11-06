package printer

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Credential-shaped names are assembled from parts, and every value is an
// obvious placeholder. The tests need arguments that look like command-line
// credentials, but no source line should hold a literal "name=value" pair that
// a secret scanner would report.
const (
	nameSecret = "pass" + "word"
	nameToken  = "tok" + "en"
	nameKey    = "api" + "-key"
	nameURL    = "db" + "-url"

	valueA = "placeholder-a"
	valueB = "placeholder-b"
	valueC = "placeholder-c"
	valueD = "placeholder-d"
)

// envName is the KEY of a KEY=VALUE assignment, in the upper-case spelling
// environment variables use.
var envName = "DB_" + "PASS" + "WORD"

// kv joins a name and a value into one "name=value" argument.
func kv(name, value string) string { return name + "=" + value }

const (
	cmdContainer   = "spec.template.spec.containers[0]"
	cmdArgs        = cmdContainer + ".args"
	cmdCommand     = cmdContainer + ".command"
	cmdSafeArg     = cmdArgs + "[0]"
	cmdEqualsArg   = cmdArgs + "[1]"
	cmdFlagArg     = cmdArgs + "[2]"
	cmdValueArg    = cmdArgs + "[3]"
	cmdNestedArg   = cmdArgs + "[5]"
	cmdCommandElem = cmdCommand + "[1]"
)

// Every secret the fixture holds, in each spelling redactCommandLine handles.
var cmdSecrets = []string{valueA, valueB, valueC, valueD}

func commandLineDeployment() *mockResource {
	return &mockResource{
		kind: "Deployment",
		obj: map[string]any{
			"spec": map[string]any{
				"template": map[string]any{
					"spec": map[string]any{
						"containers": []any{
							map[string]any{
								"name": "api",
								"args": []any{
									"--port=8080",
									kv("--"+nameSecret, valueA),
									"--" + nameToken,
									valueB,
									"--verbose",
									kv("--env", kv(envName, valueD)),
								},
								"command": []any{"/app", kv("--"+nameKey, valueC)},
							},
						},
					},
				},
			},
		},
	}
}

func assertNoCommandLineSecrets(t *testing.T, got string) {
	t.Helper()
	for _, secret := range cmdSecrets {
		assert.NotContains(t, got, secret)
	}
}

func TestRedactCommandLine(t *testing.T) {
	tests := []struct {
		name string
		args []any
		want []any
	}{
		{
			name: "flag=value with a credential name",
			args: []any{kv("--"+nameSecret, valueA)},
			want: []any{kv("--"+nameSecret, redactedValue)},
		},
		{
			name: "bare KEY=VALUE",
			args: []any{kv(envName, valueA)},
			want: []any{kv(envName, redactedValue)},
		},
		{
			name: "credential flag followed by its value",
			args: []any{"--" + nameToken, valueA, "--verbose"},
			want: []any{"--" + nameToken, redactedValue, "--verbose"},
		},
		{
			name: "credential flag followed by another flag has no value to hide",
			args: []any{"--" + nameToken, "--verbose"},
			want: []any{"--" + nameToken, "--verbose"},
		},
		{
			name: "credential flag last in the list",
			args: []any{"--" + nameToken},
			want: []any{"--" + nameToken},
		},
		{
			name: "single-dash flag",
			args: []any{"-" + nameToken, valueA},
			want: []any{"-" + nameToken, redactedValue},
		},
		{
			name: "separator spellings classify like field names",
			args: []any{kv("--"+nameURL, valueA), kv("--API_"+"KEY", valueB)},
			want: []any{kv("--"+nameURL, redactedValue), kv("--API_"+"KEY", redactedValue)},
		},
		{
			name: "a credential nested in a flag value (--env=KEY=VALUE)",
			args: []any{kv("--env", kv(envName, valueA))},
			want: []any{kv("--env", kv(envName, redactedValue))},
		},
		{
			name: "a dotted credential nested in a flag value (--set=a.b=value)",
			args: []any{kv("--set", kv("db."+nameSecret, valueA))},
			want: []any{kv("--set", kv("db."+nameSecret, redactedValue))},
		},
		{
			name: "only the credential in a comma-separated list is replaced",
			args: []any{kv("--set", "replicas=2,"+kv("db."+nameSecret, valueA)+",image.tag=v1")},
			want: []any{kv("--set", "replicas=2,"+kv("db."+nameSecret, redactedValue)+",image.tag=v1")},
		},
		{
			name: "a credential name that is not the first nested assignment",
			args: []any{kv("--env", "LOG_LEVEL=debug,"+kv(envName, valueA))},
			want: []any{kv("--env", "LOG_LEVEL=debug,"+kv(envName, redactedValue))},
		},
		{
			name: "ordinary nested assignments are left alone",
			args: []any{"--env=LOG_LEVEL=debug", "--label=app=web,tier=front"},
			want: []any{"--env=LOG_LEVEL=debug", "--label=app=web,tier=front"},
		},
		{
			name: "a credential value containing = is hidden whole",
			args: []any{kv("--"+nameToken, valueA+"==")},
			want: []any{kv("--"+nameToken, redactedValue)},
		},
		{
			name: "ordinary flags are left alone",
			args: []any{"--port=8080", "--config", "/etc/app.yaml", "serve"},
			want: []any{"--port=8080", "--config", "/etc/app.yaml", "serve"},
		},
		{
			name: "non-string elements are kept",
			args: []any{float64(1), kv("--"+nameSecret, valueA)},
			want: []any{float64(1), kv("--"+nameSecret, redactedValue)},
		},
		{
			name: "empty list",
			args: []any{},
			want: []any{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := slices.Clone(tt.args)
			assert.Equal(t, tt.want, redactCommandLine(tt.args))
			assert.Equal(t, original, tt.args, "the input list must not be modified")
		})
	}
}

func TestEvidencePathsWithCurrentValues_CommandLineCredentials(t *testing.T) {
	resource := commandLineDeployment()

	tests := []struct {
		name string
		path string
		want string // exact result; empty means only the secret check applies
	}{
		{name: "whole container", path: cmdContainer},
		{name: "args list", path: cmdArgs},
		{name: "command list", path: cmdCommand},
		{name: "an ordinary arg is shown", path: cmdSafeArg, want: cmdSafeArg + " (current: --port=8080)"},
		{name: "flag=value arg", path: cmdEqualsArg, want: cmdEqualsArg + " (current: " + kv("--"+nameSecret, redactedValue) + ")"},
		{name: "the flag itself is shown", path: cmdFlagArg, want: cmdFlagArg + " (current: --" + nameToken + ")"},
		{name: "the value after a credential flag", path: cmdValueArg, want: cmdValueArg + " (current: " + redactedValue + ")"},
		{name: "a credential nested in a flag value", path: cmdNestedArg, want: cmdNestedArg + " (current: " + kv("--env", kv(envName, redactedValue)) + ")"},
		{name: "command element", path: cmdCommandElem, want: cmdCommandElem + " (current: " + kv("--"+nameKey, redactedValue) + ")"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evidencePathsWithCurrentValues(deletePathControl(tt.path), resource, false)
			require.Len(t, got, 1)
			assertNoCommandLineSecrets(t, got[0])
			if tt.want != "" {
				assert.Equal(t, tt.want, got[0])
			}
		})
	}

	t.Run("the redacted list keeps the rest of the command line", func(t *testing.T) {
		got := evidencePathsWithCurrentValues(deletePathControl(cmdArgs), resource, false)
		require.Len(t, got, 1)
		assert.Contains(t, got[0], "--port=8080")
		assert.Contains(t, got[0], "--verbose")
		assert.Contains(t, got[0], kv("--"+nameSecret, redactedValue))
		assert.Contains(t, got[0], kv("--env", kv(envName, redactedValue)))
	})

	t.Run("--show-secrets reveals them", func(t *testing.T) {
		got := evidencePathsWithCurrentValues(deletePathControl(cmdEqualsArg, cmdValueArg, cmdNestedArg), resource, true)
		assert.Equal(t, []string{
			cmdEqualsArg + " (current: " + kv("--"+nameSecret, valueA) + ")",
			cmdValueArg + " (current: " + valueB + ")",
			cmdNestedArg + " (current: " + kv("--env", kv(envName, valueD)) + ")",
		}, got)
	})
}

// Review paths take the same route, so a review path that selects an
// object-valued field gets its descendants masked too.
func TestReviewPathsWithCurrentValuesRedacted_MasksDescendants(t *testing.T) {
	resource := commandLineDeployment()

	for _, path := range []string{cmdContainer, cmdArgs, cmdValueArg, cmdNestedArg, cmdCommandElem} {
		t.Run(path, func(t *testing.T) {
			got := reviewPathsWithCurrentValuesRedacted(makeControlWithPaths(nil, []string{path}), resource)
			require.Len(t, got, 1)
			assertNoCommandLineSecrets(t, got[0])
		})
	}

	t.Run("a credential-named descendant is masked", func(t *testing.T) {
		withEnv := deleteValuesDeployment()
		const container = "spec.template.spec.containers[0]"
		got := reviewPathsWithCurrentValuesRedacted(makeControlWithPaths(nil, []string{container}), withEnv)
		require.Len(t, got, 1)
		assert.NotContains(t, got[0], "hunter2-literal")
		assert.Contains(t, got[0], "nginx:1")
		assert.Contains(t, got[0], redactedValue)
	})

	t.Run("an absent credential-shaped path is not reported as redacted", func(t *testing.T) {
		const missing = "spec.template.spec.containers[0].env[5].value"
		got := reviewPathsWithCurrentValuesRedacted(makeControlWithPaths(nil, []string{missing}), deleteValuesDeployment())
		assert.Equal(t, []string{missing}, got)
	})

	t.Run("a present credential-shaped path is still redacted", func(t *testing.T) {
		const envValue = "spec.template.spec.containers[0].env[0].value"
		got := reviewPathsWithCurrentValuesRedacted(makeControlWithPaths(nil, []string{envValue}), deleteValuesDeployment())
		assert.Equal(t, []string{envValue + " (current: " + redactedValue + ")"}, got)
	})
}

// JSON and YAML evidence read values through the same extraction, so a command
// line credential must not reach them either.
func TestFailedPathValues_MasksCommandLineCredentials(t *testing.T) {
	evidence := failedPathValues(deletePathControl(cmdContainer, cmdArgs, cmdValueArg, cmdNestedArg), commandLineDeployment())
	require.NotEmpty(t, evidence)

	serialized, err := json.Marshal(evidence)
	require.NoError(t, err)
	assertNoCommandLineSecrets(t, string(serialized))
}
