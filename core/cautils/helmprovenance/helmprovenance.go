// Package helmprovenance recovers a best-effort link from a rendered Helm
// resource back to its source template and the .Values keys that template
// reads. It is intentionally static (regex over template text) instead of
// running the Helm template parser, because the parser fails on any unknown
// function name and real charts depend on a long tail of sprig and chart-local
// helpers that we do not want to enumerate.
//
// The output is per-template, not per-rendered-field: every resource produced
// by templates/foo.yaml carries the same set of values paths. That is enough
// for `kubescape fix` to suggest "edit .Values.X in values.yaml" without
// risking the wrong-line edits that the previous template-line-mapping code
// (removed in PR #1995) was prone to.
package helmprovenance

import (
	"bufio"
	"bytes"
	"path"
	"regexp"
	"sort"
	"strings"

	"helm.sh/helm/v3/pkg/chart"
)

// Provenance describes what we recovered for one rendered template.
type Provenance struct {
	// TemplateFile is the chart-relative source template path,
	// e.g. "templates/deployment.yaml". Matches chart.File.Name.
	TemplateFile string
	// ValuesPaths are dotted .Values.* keys statically referenced by the
	// template (and by any partials it includes, transitively). Sorted,
	// deduplicated. Empty when nothing could be statically traced.
	//
	// Caveat: segments are joined with ".", so an `index .Values` access with
	// a key that itself contains a literal dot (e.g. {{ index .Values "foo.bar"
	// "baz" }}) flattens to "foo.bar.baz" — indistinguishable from a nested
	// path foo→bar→baz. Treat these strings as advisory pointers into
	// values.yaml, not as a machine-parseable key path.
	ValuesPaths []string
	// TemplateLine is the 1-based line of the first apiVersion: occurrence
	// in the source template; 0 when not found. Useful as a stable anchor
	// when no per-field info is available.
	TemplateLine int
}

// Extract walks the chart and every dependency and returns a map keyed the
// same way helm.sh/helm/v3/pkg/engine.Render keys its output:
//
//	"<chartName>/templates/<file>"             for the root chart
//	"<chartName>/charts/<subName>/templates/.." for subcharts
//
// Partial templates (filenames starting with "_") and non-template files are
// skipped — they do not produce rendered output directly.
func Extract(c *chart.Chart) map[string]Provenance {
	if c == nil {
		return nil
	}
	partials := collectPartialRefs(c)
	out := make(map[string]Provenance)
	walk(c, c.Name(), partials, out)
	return out
}

func walk(c *chart.Chart, prefix string, partials map[string]map[string]struct{}, out map[string]Provenance) {
	for _, t := range c.Templates {
		base := path.Base(t.Name)
		if strings.HasPrefix(base, "_") {
			continue
		}
		key := prefix + "/" + t.Name
		out[key] = analyze(t.Name, t.Data, partials)
	}
	for _, dep := range c.Dependencies() {
		walk(dep, prefix+"/charts/"+dep.Name(), partials, out)
	}
}

// regexes are package-level to avoid re-compiling per call.
var (
	// .Values.foo.bar — captures the trailing ".foo.bar" segment.
	// Stops at non-identifier characters, so .Values.foo[0] yields ".foo"
	// (we cannot safely flatten array indices into a values key anyway).
	dotValuesRe = regexp.MustCompile(`\.Values((?:\.[A-Za-z_][A-Za-z0-9_]*)+)`)
	// (index .Values "foo" "bar") — the second-most common access form.
	indexValuesRe = regexp.MustCompile(`index\s+\.Values((?:\s+"[^"]+")+)`)
	// Quoted segment inside an `index .Values "x" "y"` chain.
	quotedRe = regexp.MustCompile(`"([^"]+)"`)
	// Helm partial invocations: include "name" / template "name".
	includeRe = regexp.MustCompile(`(?:include|template)\s+"([^"]+)"`)
	// Any Go-template action: {{ ... }} with optional "-" trim markers. The
	// non-greedy body lets us walk the action stream in order so we can match
	// {{ define }} / {{ end }} with depth tracking — a single regex with
	// .*? mismatches on the first inner {{ end }} from a nested if/range/with.
	actionRe = regexp.MustCompile(`(?s)\{\{-?\s*(.*?)\s*-?\}\}`)
	// First identifier inside an action body, used to classify it as a
	// block opener (define/if/range/with/block) or a closer (end).
	actionKindRe = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)`)
	// Captures the name argument of a {{ define "name" }} action. Anchored
	// because we run it on the action body, not the whole template.
	defineNameRe = regexp.MustCompile(`^define\s+"([^"]+)"`)
)

// defineBlock is one balanced {{ define }} ... {{ end }} pair.
type defineBlock struct {
	name string
	body []byte
}

// findDefines scans data for top-level {{ define "X" }} ... {{ end }} pairs,
// matching ends to openers with depth tracking so that nested {{ if }} /
// {{ range }} / {{ with }} / {{ block }} blocks inside the define do not
// prematurely terminate the body. Returns blocks in source order.
//
// Bodies of nested defines (Helm permits define-inside-define, though it is
// rare) are also returned as their own entries — they are top-level for our
// partial-resolution purposes.
func findDefines(data []byte) []defineBlock {
	actions := actionRe.FindAllSubmatchIndex(data, -1)
	if len(actions) == 0 {
		return nil
	}
	type openDefine struct {
		name     string
		bodyFrom int // index in data where body starts (just after the opening action)
		depth    int // template-block depth at the point the define opened
	}
	var (
		out   []defineBlock
		stack []openDefine
		depth int // total nesting depth across all block-opening actions
	)
	for _, a := range actions {
		// a = [actionStart, actionEnd, bodyStart, bodyEnd]
		actionStart, actionEnd := a[0], a[1]
		body := data[a[2]:a[3]]
		kindMatch := actionKindRe.FindSubmatch(body)
		if kindMatch == nil {
			continue
		}
		switch string(kindMatch[1]) {
		case "define":
			nm := defineNameRe.FindSubmatch(body)
			if nm == nil {
				// Malformed; still increment depth so a later {{ end }} balances.
				depth++
				continue
			}
			stack = append(stack, openDefine{
				name:     string(nm[1]),
				bodyFrom: actionEnd,
				depth:    depth,
			})
			depth++
		case "if", "range", "with", "block":
			depth++
		case "end":
			if depth > 0 {
				depth--
			}
			// If this end closes the most recent define (i.e., the define's
			// recorded depth equals the post-decrement depth), pop it.
			if n := len(stack); n > 0 && stack[n-1].depth == depth {
				od := stack[n-1]
				stack = stack[:n-1]
				out = append(out, defineBlock{
					name: od.name,
					body: data[od.bodyFrom:actionStart],
				})
			}
		}
	}
	return out
}

// collectPartialRefs scans every _helpers.tpl-style file across the chart and
// its dependencies, building partialName -> set of values paths it reads
// directly. Transitive resolution (a partial that includes another) is handled
// at lookup time in analyze.
func collectPartialRefs(c *chart.Chart) map[string]map[string]struct{} {
	out := map[string]map[string]struct{}{}
	var walkPartials func(c *chart.Chart)
	walkPartials = func(c *chart.Chart) {
		for _, t := range c.Templates {
			for _, blk := range findDefines(t.Data) {
				refs := out[blk.name]
				if refs == nil {
					refs = map[string]struct{}{}
					out[blk.name] = refs
				}
				for _, p := range valuePathsIn(blk.body) {
					refs[p] = struct{}{}
				}
				// Also remember which partials this partial calls; we
				// resolve the chain in analyze().
				for _, inc := range includeRe.FindAllSubmatch(blk.body, -1) {
					refs["@include:"+string(inc[1])] = struct{}{}
				}
			}
		}
		for _, dep := range c.Dependencies() {
			walkPartials(dep)
		}
	}
	walkPartials(c)
	return out
}

func analyze(templateFile string, data []byte, partials map[string]map[string]struct{}) Provenance {
	refs := map[string]struct{}{}
	for _, p := range valuePathsIn(data) {
		refs[p] = struct{}{}
	}
	// Resolve include/template calls transitively, with a visited-set guard
	// against partials that recursively include themselves (rare but legal).
	visited := map[string]struct{}{}
	var resolve func(name string)
	resolve = func(name string) {
		if _, ok := visited[name]; ok {
			return
		}
		visited[name] = struct{}{}
		for r := range partials[name] {
			if after, ok := strings.CutPrefix(r, "@include:"); ok {
				resolve(after)
				continue
			}
			refs[r] = struct{}{}
		}
	}
	for _, m := range includeRe.FindAllSubmatch(data, -1) {
		resolve(string(m[1]))
	}

	paths := make([]string, 0, len(refs))
	for r := range refs {
		paths = append(paths, r)
	}
	sort.Strings(paths)

	return Provenance{
		TemplateFile: templateFile,
		ValuesPaths:  paths,
		TemplateLine: firstApiVersionLine(data),
	}
}

// valuePathsIn pulls dotted .Values.foo.bar refs and (index .Values "x" "y")
// refs out of a chunk of template text. Returns dotted paths without the
// leading ".Values." prefix.
func valuePathsIn(data []byte) []string {
	seen := map[string]struct{}{}
	for _, m := range dotValuesRe.FindAllSubmatch(data, -1) {
		// m[1] is e.g. ".image.tag"; trim leading dot.
		p := strings.TrimPrefix(string(m[1]), ".")
		if p != "" {
			seen[p] = struct{}{}
		}
	}
	for _, m := range indexValuesRe.FindAllSubmatch(data, -1) {
		quoted := quotedRe.FindAllSubmatch(m[1], -1)
		if len(quoted) == 0 {
			continue
		}
		segs := make([]string, 0, len(quoted))
		for _, q := range quoted {
			segs = append(segs, string(q[1]))
		}
		seen[strings.Join(segs, ".")] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func firstApiVersionLine(data []byte) int {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		n++
		if bytes.HasPrefix(bytes.TrimSpace(sc.Bytes()), []byte("apiVersion:")) {
			return n
		}
	}
	return 0
}
