package scan

import (
	"bytes"
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompleteValues(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		values   []string
		expected []string
	}{
		{
			name:     "matching prefix",
			input:    "h",
			values:   []string{"low", "medium", "high", "critical"},
			expected: []string{"high"},
		},
		{
			name:     "preserve uppercase prefix",
			input:    "H",
			values:   []string{"low", "medium", "high", "critical"},
			expected: []string{"High"},
		},
		{
			name:     "preserve mixed case prefix",
			input:    "HiG",
			values:   []string{"low", "medium", "high", "critical"},
			expected: []string{"HiGh"},
		},
		{
			name:     "no match",
			input:    "xyz",
			values:   []string{"low", "medium", "high", "critical"},
			expected: nil,
		},
		{
			name:     "multiple matches",
			input:    "",
			values:   []string{"low", "medium"},
			expected: []string{"low", "medium"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := completeValues(tt.values)
			got, directive := fn(nil, nil, tt.input)

			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("got %v, want %v", got, tt.expected)
			}

			if directive != cobra.ShellCompDirectiveNoFileComp {
				t.Errorf("unexpected directive: %v", directive)
			}
		})
	}
}

func TestCompleteCommaSeparated(t *testing.T) {
	values := []string{"json", "html", "pdf", "junit"}

	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "single prefix",
			input:    "j",
			expected: []string{"json", "junit"},
		},
		{
			name:     "uppercase prefix",
			input:    "J",
			expected: []string{"Json", "Junit"},
		},
		{
			name:     "comma separated prefix",
			input:    "json,h",
			expected: []string{"json,html"},
		},
		{
			name:     "uppercase comma separated prefix",
			input:    "json,H",
			expected: []string{"json,Html"},
		},
		{
			name:     "exclude selected values",
			input:    "json,",
			expected: []string{"json,html", "json,pdf", "json,junit"},
		},
		{
			name:     "no duplicate values",
			input:    "json,j",
			expected: []string{"json,junit"},
		},
		{
			name:     "exclude selected value with whitespace",
			input:    "json ,j",
			expected: []string{"json ,junit"},
		},
		{
			name:     "exclude selected value with whitespace and case",
			input:    "JSON ,J",
			expected: []string{"JSON ,Junit"},
		},
		{
			name:     "case insensitive",
			input:    "JSON,h",
			expected: []string{"JSON,html"},
		},
		{
			name:     "no matching value",
			input:    "xyz",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := completeCommaSeparated(values)
			got, directive := fn(nil, nil, tt.input)

			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("got %v, want %v", got, tt.expected)
			}

			expectedDirective := cobra.ShellCompDirectiveNoSpace |
				cobra.ShellCompDirectiveNoFileComp

			if directive != expectedDirective {
				t.Errorf(
					"directive = %v, want %v",
					directive, expectedDirective,
				)
			}
		})
	}
}

func TestScanFormatCompletion(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    []string
		exclude []string
	}{
		{
			name: "scan suggests GitHub Actions",
			args: []string{"scan", "--format", "g"},
			want: []string{"github-actions"},
		},
		{
			name:    "image scan suggests only supported formats",
			args:    []string{"scan", "image", "--format", "g"},
			want:    []string{"gitlab-container-scanning", "github-actions"},
			exclude: []string{"gitlab-codequality"},
		},
		{
			name: "image scan suggests JSON and JUnit",
			args: []string{"scan", "image", "--format", "j"},
			want: []string{"json", "junit"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, output := newKubescapeRootWithScan(nil)
			root.SetArgs(append([]string{cobra.ShellCompRequestCmd}, tt.args...))
			require.NoError(t, root.Execute())

			lines := strings.Split(output.String(), "\n")
			for _, format := range tt.want {
				assert.Contains(t, lines, format)
			}
			for _, format := range tt.exclude {
				assert.NotContains(t, lines, format)
			}
		})
	}
}

func TestScanFormatCompletionByCommand(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		candidate   string
		wantPresent bool
	}{
		{
			name: "normal scan supports github-actions",
			args: []string{
				"__complete", "scan", "--format", "g",
			},
			candidate:   "github-actions",
			wantPresent: true,
		},
		{
			name: "image scan excludes gitlab-codequality",
			args: []string{
				"__complete", "scan", "image", "--format", "g",
			},
			candidate:   "gitlab-codequality",
			wantPresent: false,
		},
		{
			name: "image scan supports gitlab-container-scanning",
			args: []string{
				"__complete", "scan", "image", "--format", "g",
			},
			candidate:   "gitlab-container-scanning",
			wantPresent: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := &cobra.Command{Use: "kubescape"}
			root.AddCommand(GetScanCommand(nil))

			var output bytes.Buffer
			root.SetOut(&output)
			root.SetErr(io.Discard)
			root.SetArgs(tt.args)

			if err := root.Execute(); err != nil {
				t.Fatal(err)
			}

			suggestions := strings.Split(
				strings.TrimSpace(output.String()), "\n",
			)

			found := slices.Contains(suggestions, tt.candidate)
			if found != tt.wantPresent {
				t.Errorf(
					"candidate %q present = %v, want %v; output:\n%s",
					tt.candidate,
					found,
					tt.wantPresent,
					output.String(),
				)
			}
		})
	}
}

func TestCompleteCommaSeparatedLeadingComma(t *testing.T) {
	complete := completeCommaSeparated([]string{"json", "html"})

	results, _ := complete(nil, nil, ",j")

	if len(results) != 1 || results[0] != ",json" {
		t.Fatalf("expected [,json], got %v", results)
	}
}

func TestScanCommandWholeClusterPolicyCompletion(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		expected []string
	}{
		{
			name:     "empty prefix lists all policies",
			prefix:   "",
			expected: []string{"projected", "fallback", "skip", "verify"},
		},
		{
			name:     "lowercase prefix",
			prefix:   "p",
			expected: []string{"projected"},
		},
		{
			name:     "uppercase prefix preserves case",
			prefix:   "V",
			expected: []string{"Verify"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := &cobra.Command{Use: "kubescape"}
			root.AddCommand(GetScanCommand(nil))

			var output bytes.Buffer
			root.SetOut(&output)
			root.SetErr(io.Discard)
			root.SetArgs([]string{"__complete", "scan", "--whole-cluster-policy", tt.prefix})

			require.NoError(t, root.Execute())
			lines := strings.Split(strings.TrimSpace(output.String()), "\n")
			for _, want := range tt.expected {
				assert.Contains(t, lines, want)
			}
		})
	}
}
