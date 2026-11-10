package fixhandler

import (
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requireTool skips the test when a patch tool is not installed. The patch is
// only really proven by a tool that is not ours applying it.
func requireTool(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s is not installed", name)
	}
}

// applyWithGit applies patch inside dir the way a user would, and fails the
// test if git refuses it.
func applyWithGit(t *testing.T, dir, patch string) {
	t.Helper()
	cmd := exec.Command("git", "apply", "--whitespace=nowarn", "-")
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(patch)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git apply refused the patch: %s\n%s", out, patch)
}

// applyWithPatch applies patch inside dir with patch -p1.
func applyWithPatch(t *testing.T, dir, patch string) {
	t.Helper()
	cmd := exec.Command("patch", "-p1")
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(patch)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "patch refused the patch: %s\n%s", out, patch)
}

// roundTrip writes oldContent to name in a fresh directory, applies the patch
// for it with apply, and returns what the file holds afterwards.
func roundTrip(t *testing.T, apply func(*testing.T, string, string), name, oldContent, patch string) string {
	t.Helper()
	dir := t.TempDir()
	target := filepath.Join(dir, filepath.FromSlash(name))
	require.NoError(t, os.MkdirAll(filepath.Dir(target), 0o750))
	require.NoError(t, os.WriteFile(target, []byte(oldContent), 0o600))
	apply(t, dir, patch)
	got, err := os.ReadFile(target)
	require.NoError(t, err)
	return string(got)
}

const diffBase = "line 1\nline 2\nline 3\nline 4\nline 5\nline 6\nline 7\nline 8\nline 9\nline 10\n"

func TestUnifiedDiffEqualContentIsEmpty(t *testing.T) {
	assert.Empty(t, unifiedDiff("a.yaml", diffBase, diffBase))
	assert.Empty(t, unifiedDiff("a.yaml", "", ""))
	assert.Empty(t, unifiedDiff("a.yaml", "no newline", "no newline"))
}

func TestUnifiedDiffHeadersAndHunk(t *testing.T) {
	changed := strings.Replace(diffBase, "line 5\n", "LINE FIVE\n", 1)

	got := unifiedDiff("k8s/prod/pods.yaml", diffBase, changed)

	assert.Equal(t, "diff --git a/k8s/prod/pods.yaml b/k8s/prod/pods.yaml\n"+
		"--- a/k8s/prod/pods.yaml\n"+
		"+++ b/k8s/prod/pods.yaml\n"+
		"@@ -2,7 +2,7 @@\n"+
		" line 2\n line 3\n line 4\n"+
		"-line 5\n+LINE FIVE\n"+
		" line 6\n line 7\n line 8\n", got)
}

type diffCase struct {
	name     string
	old, new string
}

// diffCases is what both patch tools are made to apply. The names are plain: a
// name git has to quote is covered separately, as not every patch reads those.
func diffCases() []diffCase {
	return []diffCase{
		{"change in the middle", diffBase, strings.Replace(diffBase, "line 5\n", "changed\n", 1)},
		{"change on the first line", diffBase, strings.Replace(diffBase, "line 1\n", "changed\n", 1)},
		{"change on the last line", diffBase, strings.Replace(diffBase, "line 10\n", "changed\n", 1)},
		{"insert a line", diffBase, strings.Replace(diffBase, "line 5\n", "line 5\nadded\n", 1)},
		{"insert at the top", diffBase, "added\n" + diffBase},
		{"append at the end", diffBase, diffBase + "added\n"},
		{"delete a line", diffBase, strings.Replace(diffBase, "line 5\n", "", 1)},
		{"delete the first line", diffBase, strings.TrimPrefix(diffBase, "line 1\n")},
		{"delete the last line", diffBase, strings.TrimSuffix(diffBase, "line 10\n")},
		{"delete everything", diffBase, ""},
		{"fill an empty file", "", diffBase},
		{"two changes far apart", diffBase + strings.Repeat("filler\n", 20) + "tail\n",
			strings.Replace(diffBase, "line 2\n", "two\n", 1) + strings.Repeat("filler\n", 20) + "TAIL\n"},
		{"two changes close together", diffBase, strings.Replace(strings.Replace(diffBase, "line 3\n", "x\n", 1), "line 7\n", "y\n", 1)},
		{"two changes with the contexts touching", diffBase, strings.Replace(strings.Replace(diffBase, "line 1\n", "x\n", 1), "line 8\n", "y\n", 1)},
		{"no newline at the end of the old file", "a\nb\nc", "a\nb\nc\nd\n"},
		{"no newline at the end of the new file", "a\nb\nc\n", "a\nb\nc\nd"},
		{"no newline at the end of either file", "a\nb\nc", "a\nB\nc"},
		{"only the last line changes and has no newline", "a\nb\nc", "a\nb\nz"},
		{"only the final newline is added", "a\nb", "a\nb\n"},
		{"only the final newline is removed", "a\nb\n", "a\nb"},
		{"windows line endings", "a\r\nb\r\nc\r\n", "a\r\nB\r\nc\r\n"},
		{"blank lines and indentation", "a:\n\n  b: 1\n\n\n  c: 2\n", "a:\n\n  b: 2\n\n\n  c: 2\n  d: 3\n"},
		{"a line that looks like a diff marker", "a\n--- b\n+++ c\n@@ -1 +1 @@\n", "a\n--- b\n+++ C\n@@ -1 +1 @@\n"},
		{"repeated lines", "x\nx\nx\nx\nx\n", "x\nx\ny\nx\nx\nx\n"},
	}
}

func TestUnifiedDiffAppliesToTheOriginal(t *testing.T) {
	requireTool(t, "git")

	for _, tt := range diffCases() {
		t.Run(tt.name, func(t *testing.T) {
			patch := unifiedDiff("deploy.yaml", tt.old, tt.new)
			require.NotEmpty(t, patch)
			assert.Equal(t, tt.new, roundTrip(t, applyWithGit, "deploy.yaml", tt.old, patch))
		})
	}
}

// TestUnifiedDiffAppliesWithPatch holds patch -p1 to the same cases git is:
// what the file holds afterwards must equal the new content byte for byte, line
// endings and a missing final newline included.
func TestUnifiedDiffAppliesWithPatch(t *testing.T) {
	requireTool(t, "patch")

	for _, tt := range diffCases() {
		t.Run(tt.name, func(t *testing.T) {
			patch := unifiedDiff("k8s/deploy.yaml", tt.old, tt.new)
			require.NotEmpty(t, patch)
			assert.Equal(t, tt.new, roundTrip(t, applyWithPatch, "k8s/deploy.yaml", tt.old, patch))
		})
	}
}

// isGNUPatch reports whether patch is GNU patch. Only it is known to read the
// file names git quotes; the BSD one that ships with macOS refuses them.
func isGNUPatch() bool {
	out, err := exec.Command("patch", "--version").CombinedOutput()
	return err == nil && strings.Contains(string(out), "GNU patch")
}

func TestUnifiedDiffQuotedNamesWithPatch(t *testing.T) {
	requireTool(t, "patch")
	if !isGNUPatch() {
		t.Skip("the installed patch is not GNU patch, which is the one that reads quoted file names")
	}
	changed := strings.Replace(diffBase, "line 5\n", "changed\n", 1)

	for _, name := range []string{"quote\"d.yaml", "tab\tname.yaml", "back\\slash.yaml"} {
		t.Run(name, func(t *testing.T) {
			patch := unifiedDiff(name, diffBase, changed)
			assert.Equal(t, changed, roundTrip(t, applyWithPatch, name, diffBase, patch))
		})
	}
}

// TestUnifiedDiffFileNames pins the file name forms git has to be able to read
// back: a name with a space, and one that has to be quoted.
func TestUnifiedDiffFileNames(t *testing.T) {
	requireTool(t, "git")
	changed := strings.Replace(diffBase, "line 5\n", "changed\n", 1)

	for _, name := range []string{"my manifests/web app.yaml", "quote\"d.yaml", "tab\tname.yaml", "back\\slash.yaml", "naïve/ünï.yaml"} {
		t.Run(name, func(t *testing.T) {
			patch := unifiedDiff(name, diffBase, changed)
			assert.Equal(t, changed, roundTrip(t, applyWithGit, name, diffBase, patch))
		})
	}
}

func TestUnifiedDiffNamesAreQuotedOrTerminated(t *testing.T) {
	assert.Contains(t, unifiedDiff("a b.yaml", "x\n", "y\n"), "--- a/a b.yaml\t\n", "a name with a space ends with a tab, as diff writes it")
	assert.Contains(t, unifiedDiff("q\"x.yaml", "x\n", "y\n"), `--- "a/q\"x.yaml"`)
	assert.NotContains(t, unifiedDiff("plain.yaml", "x\n", "y\n"), "\t\n", "a plain name has no terminator")
}

// TestUnifiedDiffCarriesNoMetadata: the patch is shared, so it must hold the
// paths and the content and nothing about the machine or the user that made it.
func TestUnifiedDiffCarriesNoMetadata(t *testing.T) {
	patch := unifiedDiff("deploy.yaml", "a\n", "b\n")

	for _, line := range strings.Split(strings.TrimSuffix(patch, "\n"), "\n") {
		assert.True(t, strings.HasPrefix(line, "diff --git a/") || strings.HasPrefix(line, "--- a/") ||
			strings.HasPrefix(line, "+++ b/") || strings.HasPrefix(line, "@@ ") ||
			strings.HasPrefix(line, "-") || strings.HasPrefix(line, "+") || strings.HasPrefix(line, " "),
			"unexpected line %q", line)
	}
	assert.NotContains(t, patch, "index ")
	assert.NotContains(t, patch, os.Getenv("USER")+"@")
}

// TestUnifiedDiffRandomEdits applies many random edits and requires every one to
// round trip, which hunk boundaries and end-of-file handling are easy to get
// wrong on. The seed is fixed so a failure reproduces.
func TestUnifiedDiffRandomEdits(t *testing.T) {
	requireTool(t, "git")
	rng := rand.New(rand.NewSource(4711)) //nolint:gosec // G404: a seeded generator makes this test reproducible; it is test input, not a secret.

	words := []string{"a", "b", "c", "d", "", "  e", "f: 1"}
	randomFile := func() string {
		var b strings.Builder
		for n := rng.Intn(30); n > 0; n-- {
			b.WriteString(words[rng.Intn(len(words))] + "\n")
		}
		return b.String()
	}
	for i := 0; i < 80; i++ {
		oldContent := randomFile()
		lines := strings.SplitAfter(oldContent, "\n")
		for e := rng.Intn(5) + 1; e > 0 && len(lines) > 0; e-- {
			at := rng.Intn(len(lines))
			switch rng.Intn(3) {
			case 0:
				lines[at] = words[rng.Intn(len(words))] + "\n"
			case 1:
				lines[at] = ""
			default:
				lines[at] += "inserted\n"
			}
		}
		newContent := strings.Join(lines, "")
		if rng.Intn(4) == 0 {
			newContent = strings.TrimSuffix(newContent, "\n")
		}
		if oldContent == newContent {
			continue
		}

		patch := unifiedDiff("f.yaml", oldContent, newContent)
		require.Equal(t, newContent, roundTrip(t, applyWithGit, "f.yaml", oldContent, patch), "edit %d\nold: %q\nnew: %q", i, oldContent, newContent)
	}
}

func TestUnifiedDiffLargeFile(t *testing.T) {
	requireTool(t, "git")
	var old strings.Builder
	for i := 0; i < 50000; i++ {
		old.WriteString("key" + strings.Repeat("x", i%7) + ": value\n")
	}
	changed := strings.Replace(old.String(), "key: value\n", "key: changed\n", 1)
	require.NotEqual(t, old.String(), changed)

	patch := unifiedDiff("big.yaml", old.String(), changed)

	assert.Less(t, len(patch), 1024, "one changed line must not make a large patch")
	assert.Equal(t, changed, roundTrip(t, applyWithGit, "big.yaml", old.String(), patch))
}

func TestSplitLines(t *testing.T) {
	assert.Nil(t, splitLines(""))
	assert.Equal(t, []string{"a\n"}, splitLines("a\n"))
	assert.Equal(t, []string{"a\n", "b"}, splitLines("a\nb"))
	assert.Equal(t, []string{"\n", "\n"}, splitLines("\n\n"))
}
