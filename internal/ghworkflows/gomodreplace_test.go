package ghworkflows

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/mod/modfile"
)

// These tests guard the replace directives in go.mod, the one line in the
// repository that decides whose source code is compiled into the binary.
//
// A replace outranks every require: whatever version dependabot bumps a module
// to, the build uses the replacement instead. That makes it the quietest way to
// change who the project trusts, and go.mod has gained replaces inside
// unrelated changes more than once:
//
//   - 1c531c92, a dependabot moby/buildkit bump, also gained a hand-added
//     `replace github.com/containerd/containerd => github.com/Retr0-Xd/...`: a
//     personal fork outside the kubescape organisation, with no comment saying
//     why. The reason was reconstructed months later in #3940; until then
//     nobody could tell whether it was safe to drop.
//   - #3218, a cluster-context helper fix, redirected kubescape/k8s-interface
//     to a contributor's fork for seventeen days.
//   - #3349, a Terraform loader fix, pinned distribution/reference to v0.5.0,
//     a downgrade from the v0.6.0 the graph otherwise selects, with no reason
//     recorded anywhere.
//
// None of them was the subject of the PR that added it, and a replace reads
// like build plumbing, so none drew a review of its own. These tests make it a decision instead:
// every replace must be listed in approvedGoModReplacements (so the diff that
// adds one also touches this file), and every replace must carry a comment in
// go.mod saying why it exists (so the next reader does not have to dig through
// history to find out whether it can go).
//
// go.mod is not in 00-pr-scanner.yaml's paths-ignore, so a PR that edits it
// runs `go test ./...` and therefore this file. The one exception is a run
// triggered by the `kubescape` account: a-pr-scanner.yaml's unit-tests job has
// skipped that actor since #1624, which skips the whole Go test suite, not just
// this guard. A go.mod change from that account is still caught by
// repo-hygiene.yaml's monthly scheduled run on master, after merge rather than
// before. The exception predates this guard (#3992) and is outside its scope.
//
// Deliberately test-only: this is a repository-hygiene guard, so it adds no
// production surface.

// approvedGoModReplacements maps each module go.mod replaces to the module path
// it is allowed to be replaced with. The version is deliberately not part of
// the approval: moving a fork forward to a newer commit is routine maintenance,
// whereas pointing a module at a different owner is the decision a reviewer
// needs to see.
//
// A same-path entry is a version pin (upstream code, held at a chosen version).
var approvedGoModReplacements = map[string]string{
	// Forks carrying the image-scanning and cosign changes kubescape needs.
	"github.com/anchore/stereoscope":         "github.com/matthyx/stereoscope",
	"github.com/google/go-containerregistry": "github.com/matthyx/go-containerregistry",

	// Load-bearing until the stereoscope fork stops pulling in containerd v1;
	// see #3940.
	"github.com/containerd/containerd": "github.com/Retr0-Xd/containerd",

	"github.com/distribution/reference": "github.com/distribution/reference",
}

// replaceProblems reports every replace directive in f that is not approved, or
// that go.mod does not explain, plus every approval that no longer matches a
// replace. It is separate from the tests over the real go.mod so the rules
// themselves can be exercised against synthetic files.
func replaceProblems(f *modfile.File, approved map[string]string) []string {
	var problems []string

	blockComments := replaceBlockComments(f)
	seen := make(map[string]bool, len(f.Replace))
	for _, r := range f.Replace {
		old, repl := r.Old.Path, r.New.Path
		seen[old] = true

		directive := fmt.Sprintf("replace %s => %s", old, repl)
		if r.New.Version != "" {
			directive += " " + r.New.Version
		}

		want, ok := approved[old]
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf(
				"%q is not approved: it redirects %s to code the project has not agreed to build from; "+
					"either remove it or add %q => %q to approvedGoModReplacements", directive, old, old, repl))
		case r.New.Version == "":
			// A filesystem replacement only resolves inside this checkout and
			// makes `go install` of the module fail outright.
			problems = append(problems, fmt.Sprintf(
				"%q points at a local directory, which breaks `go install` for every consumer", directive))
		case want != repl:
			problems = append(problems, fmt.Sprintf(
				"%q changes the replacement of %s from the approved %q to %q; "+
					"a new owner needs its own approval in approvedGoModReplacements", directive, old, want, repl))
		}

		if !hasExplanation(r.Syntax, blockComments[r.Syntax]) {
			problems = append(problems, fmt.Sprintf(
				"%q has no comment in go.mod explaining why it exists; "+
					"add one directly above it (what it fixes, and what would let it be removed)", directive))
		}
	}

	var stale []string
	for old := range approved {
		if !seen[old] {
			stale = append(stale, old)
		}
	}
	sort.Strings(stale)
	for _, old := range stale {
		problems = append(problems, fmt.Sprintf(
			"approvedGoModReplacements still lists %s, which go.mod no longer replaces; "+
				"drop the entry so a later re-addition needs approving again", old))
	}

	return problems
}

// replaceBlockComments maps each directive inside a `replace ( ... )` block to
// the comments above that block. modfile.Line does not link back to its block,
// so the association has to be rebuilt from the syntax tree.
func replaceBlockComments(f *modfile.File) map[*modfile.Line][]modfile.Comment {
	out := make(map[*modfile.Line][]modfile.Comment)
	for _, stmt := range f.Syntax.Stmt {
		block, ok := stmt.(*modfile.LineBlock)
		if !ok || len(block.Token) == 0 || block.Token[0] != "replace" {
			continue
		}
		for _, line := range block.Line {
			out[line] = block.Before
		}
	}

	return out
}

// hasExplanation reports whether a replace line carries a non-empty comment,
// either on the lines above it, at the end of the line, or - for a directive
// inside a `replace ( ... )` block - above the block.
func hasExplanation(line *modfile.Line, blockComments []modfile.Comment) bool {
	if line == nil {
		return false
	}

	comments := append([]modfile.Comment{}, line.Before...)
	comments = append(comments, line.Suffix...)
	comments = append(comments, blockComments...)

	for _, c := range comments {
		if strings.TrimSpace(strings.TrimPrefix(c.Token, "//")) != "" {
			return true
		}
	}

	return false
}

// TestGoModReplacementsAreApprovedAndExplained is the guard over the real go.mod.
func TestGoModReplacementsAreApprovedAndExplained(t *testing.T) {
	f := parseModule(t, rootModuleFile)

	for _, problem := range replaceProblems(f, approvedGoModReplacements) {
		t.Errorf("%s: %s", rootModuleFile, problem)
	}
}

// TestReplaceProblems exercises the rules against synthetic go.mod files,
// starting with the exact change 1c531c92 made.
func TestReplaceProblems(t *testing.T) {
	approved := map[string]string{
		"example.com/forked": "example.com/fork-owner/forked",
		"example.com/pinned": "example.com/pinned",
	}

	tests := []struct {
		name  string
		gomod string
		want  []string // substrings, one per expected problem, in order
	}{
		{
			name: "approved and explained",
			gomod: `// Carries a fix not yet released upstream.
replace example.com/forked => example.com/fork-owner/forked v0.0.0-20260101000000-abcdef123456

replace example.com/pinned => example.com/pinned v0.5.0 // v0.6.0 breaks the build
`,
		},
		{
			name: "block comment explains every directive in the block",
			gomod: `// Both are needed until upstream tags a release.
replace (
	example.com/forked => example.com/fork-owner/forked v1.2.3
	example.com/pinned => example.com/pinned v0.5.0
)
`,
		},
		{
			name: "unapproved personal fork added without a comment, as in 1c531c92",
			gomod: `// Carries a fix not yet released upstream.
replace example.com/forked => example.com/fork-owner/forked v1.2.3

// Held back on purpose.
replace example.com/pinned => example.com/pinned v0.5.0

replace github.com/containerd/containerd => github.com/Retr0-Xd/containerd v0.0.0-20260322054632-16583c73e9b8
`,
			want: []string{
				`"replace github.com/containerd/containerd => github.com/Retr0-Xd/containerd v0.0.0-20260322054632-16583c73e9b8" is not approved`,
				`"replace github.com/containerd/containerd => github.com/Retr0-Xd/containerd v0.0.0-20260322054632-16583c73e9b8" has no comment in go.mod`,
			},
		},
		{
			name: "approved fork moved to a newer commit",
			gomod: `// Carries a fix not yet released upstream.
replace example.com/forked => example.com/fork-owner/forked v0.0.0-20270101000000-fedcba654321

// Held back on purpose.
replace example.com/pinned => example.com/pinned v0.5.1
`,
		},
		{
			name: "approved module moved to a different owner",
			gomod: `// Carries a fix not yet released upstream.
replace example.com/forked => example.com/someone-else/forked v1.2.3

// Held back on purpose.
replace example.com/pinned => example.com/pinned v0.5.0
`,
			want: []string{`from the approved "example.com/fork-owner/forked" to "example.com/someone-else/forked"`},
		},
		{
			name: "local directory replacement",
			gomod: `// Carries a fix not yet released upstream.
replace example.com/forked => ../forked

// Held back on purpose.
replace example.com/pinned => example.com/pinned v0.5.0
`,
			want: []string{`points at a local directory`},
		},
		{
			name: "empty comment is not an explanation",
			gomod: `//
replace example.com/forked => example.com/fork-owner/forked v1.2.3

// Held back on purpose.
replace example.com/pinned => example.com/pinned v0.5.0
`,
			want: []string{`"replace example.com/forked => example.com/fork-owner/forked v1.2.3" has no comment`},
		},
		{
			name: "stale approval",
			gomod: `// Held back on purpose.
replace example.com/pinned => example.com/pinned v0.5.0
`,
			want: []string{`still lists example.com/forked`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := modfile.Parse("go.mod", []byte("module example.com/m\n\ngo 1.26\n\n"+tt.gomod), nil)
			require.NoError(t, err)

			got := replaceProblems(f, approved)
			require.Lenf(t, got, len(tt.want), "problems: %q", got)
			for i, want := range tt.want {
				assert.Contains(t, got[i], want)
			}
		})
	}
}
