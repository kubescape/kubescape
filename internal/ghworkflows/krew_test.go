// Package ghworkflows holds repository-hygiene tests. These ones guard
// .krew.yaml, the plugin manifest template krew-release-bot renders when it
// opens a version-bump pull request against kubernetes-sigs/krew-index.
//
// The template could not render at all. It called addURIAndSha with four
// arguments against a function that takes two, and KREW_RELEASE.md documented a
// `trimPrefix "v"` binding for a template environment whose function map holds
// only `indent` and `addURIAndSha` - no sprig, so no trimPrefix. Each form
// fails a different way (execution error, parse error) and the file and its own
// documentation disagreed about which to use.
//
// None of that surfaced, for two compounding reasons. 02-release.yaml passes
// `krew_template_file: dist/krew/kubescape.yaml` - the manifest GoReleaser
// writes from its own `krews:` block - so releases never touch .krew.yaml and
// krew-index stayed correct while the template rotted. And the action documents
// that input as defaulting to .krew.yaml, so dropping that one workflow line
// would have silently promoted a file that cannot render into the release path.
//
// The asset names are the other half. GoReleaser's default archive name is
// {{.ProjectName}}_{{.Version}}_{{.Os}}_{{.Arch}}, and .Version is the tag
// without its leading "v", so a release publishes kubescape_4.0.12_linux_amd64
// while the tag is v4.0.12. A template that interpolates .TagName into the file
// name asks for an asset that does not exist.
//
// These tests reproduce krew-release-bot's template environment offline - the
// same two functions, the same nested-template URL rendering - so a wrong
// argument count, an undefined function, or a drifted asset name fails on the
// pull request that introduces it rather than at the next tag.
//
// Deliberately test-only: this is a repository-hygiene guard, so it adds no
// production surface.
package ghworkflows

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const (
	krewTemplateName = ".krew.yaml"

	// krewDocName documents the template. It embeds a copy of it, which is
	// exactly the arrangement that drifted, so the copy is asserted against the
	// file rather than trusted to be updated alongside it.
	krewDocName = "KREW_RELEASE.md"

	// krewSampleTag renders the template for a tag that has actually shipped, so
	// the expected asset names below can be checked against a published release
	// and against kubernetes-sigs/krew-index/plugins/kubescape.yaml.
	krewSampleTag = "v4.0.12"

	// krewSampleVersion is krewSampleTag as GoReleaser's .Version renders it.
	krewSampleVersion = "4.0.12"

	// krewReleaseDownloadPrefix is where every published asset is served from.
	krewReleaseDownloadPrefix = "https://github.com/kubescape/kubescape/releases/download"

	// krewStubSha stands in for the checksum the real addURIAndSha computes by
	// downloading the asset. These tests assert on names and structure, which
	// need no network.
	krewStubSha = "0000000000000000000000000000000000000000000000000000000000000000"

	// addURIAndShaCall identifies the template lines that build an asset URL, in
	// both the template and its documented copy.
	addURIAndShaCall = "addURIAndSha"
)

// krewPlatform is one entry of the plugin manifest's `platforms` list. The
// binary name differs on Windows, which is the only reason the manifest carries
// six entries rather than one per os/arch pair generated from a matrix.
type krewPlatform struct {
	os     string
	arch   string
	binary string
}

// krewPlatforms is the set of platforms .goreleaser.yaml builds the `cli`
// artifact for: goos linux/darwin/windows crossed with goarch amd64/arm64.
var krewPlatforms = []krewPlatform{
	{os: "linux", arch: "amd64", binary: "kubescape"},
	{os: "linux", arch: "arm64", binary: "kubescape"},
	{os: "darwin", arch: "amd64", binary: "kubescape"},
	{os: "darwin", arch: "arm64", binary: "kubescape"},
	{os: "windows", arch: "amd64", binary: "kubescape.exe"},
	{os: "windows", arch: "arm64", binary: "kubescape.exe"},
}

// krewReleaseRequest mirrors the fields of krew-release-bot's ReleaseRequest,
// the value it executes the template against. Only TagName is used today;
// the rest are present so referencing one is not a spurious failure here.
type krewReleaseRequest struct {
	TagName    string
	PluginName string
	PluginRepo string
}

// krewPluginSpec is the subset of the rendered manifest these tests assert on.
// It is the shape krew itself consumes, so parsing into it proves the template
// produced a plugin manifest and not merely well-formed YAML.
type krewPluginSpec struct {
	Spec struct {
		Version   string `yaml:"version"`
		Platforms []struct {
			URI      string `yaml:"uri"`
			Sha256   string `yaml:"sha256"`
			Bin      string `yaml:"bin"`
			Selector struct {
				MatchLabels struct {
					OS   string `yaml:"os"`
					Arch string `yaml:"arch"`
				} `yaml:"matchLabels"`
			} `yaml:"selector"`
		} `yaml:"platforms"`
	} `yaml:"spec"`
}

// krewRender collects what a template execution produced: the URLs
// addURIAndSha was asked to resolve, and any error raised while resolving them.
// Errors are recorded rather than panicked, unlike upstream, because a panic
// out of a template function crosses the test binary rather than failing a test.
type krewRender struct {
	uris []string
	errs []error
}

// krewFuncs reproduces krew-release-bot's template function map exactly - see
// pkg/source/template.go in rajatjindal/krew-release-bot. Both the signatures
// and the omissions are load-bearing: addURIAndSha takes two arguments, and
// nothing else is defined, so a four-argument call or a `trimPrefix` reference
// fails here the same way it fails in the bot.
func krewFuncs(render *krewRender) template.FuncMap {
	return template.FuncMap{
		// indent matches upstream, including its fixShaIndentation step: the
		// sha256 line addURIAndSha emits carries a hardcoded 4-space pad that is
		// stripped before re-padding.
		"indent": func(spaces int, v string) string {
			v = strings.ReplaceAll(v, "    sha256:", "sha256:")
			pad := strings.Repeat(" ", spaces)
			return strings.TrimSpace(pad + strings.ReplaceAll(v, "\n", "\n"+pad))
		},
		"addURIAndSha": func(url, tag string) string {
			// The url argument is itself a template, rendered against a value
			// carrying only TagName and with no functions at all. Anything the
			// outer template needs to compute - the "v"-less version among them -
			// has to be interpolated before it gets here.
			inner, err := template.New("url").Parse(url)
			if err != nil {
				render.errs = append(render.errs, fmt.Errorf("parsing url template %q: %w", url, err))
				return ""
			}

			buf := new(bytes.Buffer)
			if err := inner.Execute(buf, struct{ TagName string }{TagName: tag}); err != nil {
				render.errs = append(render.errs, fmt.Errorf("executing url template %q: %w", url, err))
				return ""
			}

			render.uris = append(render.uris, buf.String())

			// Upstream's exact return shape. The 4-space pad before sha256 is what
			// aligns it under the `uri:` line the template call is indented to.
			return fmt.Sprintf("uri: %s\n    sha256: %s", buf.String(), krewStubSha)
		},
	}
}

func krewTemplatePath(t *testing.T) string {
	t.Helper()

	return filepath.Join(repoRoot(t), krewTemplateName)
}

// renderKrewTemplate parses and executes .krew.yaml the way krew-release-bot
// does, and fails the test with the template engine's own message if it cannot.
// Upstream names the template after the file's base name and loads it with
// ParseFiles, so this does too; Execute resolves the wrong name otherwise.
func renderKrewTemplate(t *testing.T, tag string) (string, *krewRender) {
	t.Helper()

	path := krewTemplatePath(t)
	render := &krewRender{}

	parsed, err := template.New(filepath.Base(path)).Funcs(krewFuncs(render)).ParseFiles(path)
	require.NoErrorf(t, err, "%s does not parse under krew-release-bot's function map; "+
		"the bot would fail the same way and open no krew-index pull request", krewTemplateName)

	buf := new(bytes.Buffer)
	require.NoErrorf(t, parsed.Execute(buf, krewReleaseRequest{TagName: tag}),
		"%s does not render for tag %s; the bot would fail the same way and open no krew-index "+
			"pull request", krewTemplateName, tag)

	for _, renderErr := range render.errs {
		assert.NoErrorf(t, renderErr, "%s built a URL that addURIAndSha cannot resolve", krewTemplateName)
	}

	return buf.String(), render
}

// expectedKrewURI is the asset URL a release actually publishes: the tag in the
// path, and GoReleaser's .Version - the tag without its "v" - in the file name.
func expectedKrewURI(tag, version string, platform krewPlatform) string {
	return fmt.Sprintf("%s/%s/kubescape_%s_%s_%s.tar.gz",
		krewReleaseDownloadPrefix, tag, version, platform.os, platform.arch)
}

// addURIAndShaLines returns every asset-URL-building line in content, trimmed,
// so the template and its documented copy can be compared without depending on
// indentation or ordering. A line has to open with an action to count, which is
// what separates a template line in the documented copy from prose that merely
// mentions addURIAndSha while explaining it.
func addURIAndShaLines(content string) []string {
	var lines []string
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "{{") && strings.Contains(trimmed, addURIAndShaCall) {
			lines = append(lines, trimmed)
		}
	}

	return lines
}

// TestKrewTemplateRendersUnderReleaseBotFuncs is the direct regression test.
// The shipped template called addURIAndSha with four arguments against a
// two-argument function, so it could never render; the documented alternative
// referenced trimPrefix, which is not defined in this environment either.
func TestKrewTemplateRendersUnderReleaseBotFuncs(t *testing.T) {
	_, render := renderKrewTemplate(t, krewSampleTag)

	assert.Lenf(t, render.uris, len(krewPlatforms),
		"%s resolved %d asset URLs, expected one per platform (%d); a platform that builds no URL "+
			"installs nothing through krew", krewTemplateName, len(render.uris), len(krewPlatforms))
}

// TestKrewTemplateURIsMatchGoreleaserAssetNames closes the gap the issue
// reported: a template can render perfectly and still name assets that were
// never published. The expected names here match the release v4.0.12 published
// and the entry it produced in kubernetes-sigs/krew-index.
func TestKrewTemplateURIsMatchGoreleaserAssetNames(t *testing.T) {
	_, render := renderKrewTemplate(t, krewSampleTag)

	expected := make([]string, 0, len(krewPlatforms))
	for _, platform := range krewPlatforms {
		expected = append(expected, expectedKrewURI(krewSampleTag, krewSampleVersion, platform))
	}

	assert.ElementsMatchf(t, expected, render.uris,
		"%s builds asset URLs that do not match what GoReleaser publishes; addURIAndSha downloads "+
			"each one to checksum it, so a wrong name fails the release with a 404 instead of "+
			"opening a krew-index pull request", krewTemplateName)
}

// TestKrewTemplateRendersValidPluginManifest checks the output is a manifest
// krew can consume, not just valid YAML. It is the guard on indentation: the
// sha256 line addURIAndSha emits is padded by exactly four spaces, so an entry
// indented differently silently reparents sha256 or breaks the document.
func TestKrewTemplateRendersValidPluginManifest(t *testing.T) {
	rendered, _ := renderKrewTemplate(t, krewSampleTag)

	var manifest krewPluginSpec
	require.NoErrorf(t, yaml.Unmarshal([]byte(rendered), &manifest),
		"%s renders invalid YAML:\n%s", krewTemplateName, rendered)

	assert.Equalf(t, krewSampleTag, manifest.Spec.Version,
		"spec.version must be the tag; krew-index rejects a manifest whose version does not match "+
			"the release it points at")

	require.Lenf(t, manifest.Spec.Platforms, len(krewPlatforms),
		"%s rendered %d platforms, expected %d",
		krewTemplateName, len(manifest.Spec.Platforms), len(krewPlatforms))

	for _, platform := range manifest.Spec.Platforms {
		t.Run(platform.Selector.MatchLabels.OS+"/"+platform.Selector.MatchLabels.Arch, func(t *testing.T) {
			assert.NotEmpty(t, platform.URI, "platform has no uri, so krew has nothing to download")
			assert.Equalf(t, krewStubSha, platform.Sha256,
				"platform has no sha256 at the expected nesting; addURIAndSha pads it by four spaces, "+
					"so the template call must sit at that indentation")
			assert.NotEmpty(t, platform.Bin, "platform declares no bin, so krew cannot link the plugin")
		})
	}
}

// TestKrewDocMatchesTemplate is the drift guard proper. KREW_RELEASE.md embeds a
// copy of the template and instructs contributors to edit .krew.yaml, so the two
// have to agree - the reported bug was precisely the file having drifted from
// its own documentation, with each carrying a different unrenderable form.
func TestKrewDocMatchesTemplate(t *testing.T) {
	templateContent, err := os.ReadFile(krewTemplatePath(t))
	require.NoErrorf(t, err, "cannot read %s", krewTemplateName)

	docPath := filepath.Join(repoRoot(t), krewDocName)
	docContent, err := os.ReadFile(docPath)
	require.NoErrorf(t, err, "cannot read %s", krewDocName)

	fromTemplate := addURIAndShaLines(string(templateContent))
	require.NotEmptyf(t, fromTemplate, "%s builds no asset URLs at all", krewTemplateName)

	fromDoc := addURIAndShaLines(string(docContent))
	require.NotEmptyf(t, fromDoc,
		"%s no longer shows any %s call; it documents the template, so it has to show the real one",
		krewDocName, addURIAndShaCall)

	assert.ElementsMatchf(t, fromTemplate, fromDoc,
		"%s documents a different template than %s ships; a contributor following the documentation "+
			"would reintroduce the form that cannot render", krewDocName, krewTemplateName)
}

// TestGoreleaserArchivesUseDefaultNaming pins the assumption the asset-name test
// rests on. With no name_template, GoReleaser uses
// {{.ProjectName}}_{{.Version}}_{{.Os}}_{{.Arch}}, and .Version is the tag minus
// its "v" - which is the whole reason .krew.yaml has to trim the tag. Setting a
// name_template here would rename every published asset and leave .krew.yaml
// pointing at the old names, so it must fail until both are updated together.
func TestGoreleaserArchivesUseDefaultNaming(t *testing.T) {
	config := loadGoreleaserConfig(t)

	require.NotEmptyf(t, config.Archives, "%s declares no archives; there would be no .tar.gz for krew "+
		"to install", goreleaserConfigName)

	for _, archive := range config.Archives {
		assert.Emptyf(t, archive.NameTemplate,
			"archive %q sets name_template %q, so published asset names no longer follow "+
				"{{.ProjectName}}_{{.Version}}_{{.Os}}_{{.Arch}}; update the printf in %s to match, "+
				"then update this test", archive.ID, archive.NameTemplate, krewTemplateName)
	}
}
