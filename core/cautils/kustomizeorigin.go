package cautils

import (
	"bytes"
	"encoding/json"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/pkg/pathcontainment"
	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/api/provider"
	"sigs.k8s.io/kustomize/api/resmap"
	"sigs.k8s.io/kustomize/api/types"
	"sigs.k8s.io/kustomize/kyaml/filesys"
	kyaml "sigs.k8s.io/kustomize/kyaml/yaml"
)

// Kustomize writes the file a resource came from into this annotation when the
// kustomization asks for it with buildMetadata: [originAnnotations]. A scanned
// kustomization that does not ask is rendered through a wrapper that asks on
// Kubescape's behalf (see renderWithOrigins), and the annotation is removed
// again before the resource goes anywhere else. One that does ask keeps it,
// because its own build produces it.
const kustomizeOriginAnnotation = "config.kubernetes.io/origin"

// kustomizeOrigin is the part of Kustomize's origin annotation that names a file.
type kustomizeOrigin struct {
	// Path is the file the resource was read from, relative to the directory the
	// build was started in. For a resource that a generator made it is the
	// kustomization file that configured the generator.
	Path string `yaml:"path,omitempty"`
	// Repo is set when the resource came from a remote repository, in which case
	// Path is a path inside that repository and not a file on this machine.
	Repo string `yaml:"repo,omitempty"`
	// ConfiguredIn is the generator or transformer config file, for a resource a
	// plugin generated.
	ConfiguredIn string `yaml:"configuredIn,omitempty"`
}

// originMode is how Kubescape can learn where a rendered resource came from
// without changing what the scanned kustomization produces.
type originMode int

const (
	// originUnavailable means there is no way to learn the origin that leaves the
	// rendered resources exactly as the plain build renders them. The resources
	// are attributed to the directory.
	originUnavailable originMode = iota
	// originWrapper means the build runs through a wrapper that turns origin
	// annotations on, and the annotations are removed from the result.
	originWrapper
	// originOwn means the scanned kustomization already asks for origin
	// annotations, so the plain build carries them. They are read and left in
	// place, since the user asked for them.
	originOwn
)

// originPlan is what originModeFor decides for one scanned directory.
type originPlan struct {
	mode originMode
	// preserved is the scanned kustomization's own buildMetadata, which the
	// wrapper has to repeat so that the resources carry what the plain build
	// would have given them.
	preserved []string
	// allowedRoots are the directory roots that resources in this plan may originate from.
	allowedRoots []string
	// sources maps each path an origin annotation can name to the file
	// Kustomize reads there (see originWalk.sources).
	sources map[string]string
}

type inspectKey struct {
	loaderDir string
	config    string
	// lexicalDir is the path Kustomize's origin annotations give the node's
	// directory. The same kustomization reached under two names is inspected
	// under each, so both names are recorded.
	lexicalDir string
}

// originWalk is the state of one inspection of a kustomization graph.
type originWalk struct {
	visited  map[inspectKey]struct{}
	visiting map[inspectKey]struct{}
	// allowedDirs are the directories the walk inspected.
	allowedDirs []string
	// sources maps each local file an origin annotation can name, as an
	// absolute path, to the file Kustomize reads when the build reaches it,
	// with links resolved. Kustomize builds the annotation by joining the
	// references it followed as text, so the name and the file differ when a
	// reference goes through a directory link and then climbs out of it with
	// "..": the name climbs out of the link, while Kustomize, which resolved
	// the link, climbs out of its target. A name that two different files share
	// maps to "", since it does not say which one a resource came from.
	sources map[string]string
}

func (w *originWalk) recordSource(lexical, read string) {
	lexical, err := filepath.Abs(lexical)
	if err != nil {
		return
	}
	if known, ok := w.sources[lexical]; ok && known != read {
		w.sources[lexical] = ""
		return
	}
	w.sources[lexical] = read
}

// originModeFor inspects the scanned kustomization and its configuration graph
// (referenced bases and components included) to decide how its resources'
// origins can be learned safely. Kustomize hands the outermost kustomization's
// buildMetadata to every kustomization below it, so a wrapper that set its own
// list would replace the scanned one.
//
//   - Nothing requested: use the wrapper.
//   - Only managedByLabel: use the wrapper and repeat the option, so the label is
//     still added.
//   - originAnnotations requested: the plain build already records the origin.
//   - Anything else, transformerAnnotations in particular: no wrapper. Its
//     annotation holds paths that are relative to the build's root, which the
//     wrapper changes, so the wrapper would hand a rule different input.
//
// Whatever the mode, anything in the graph that could alter or forge origin
// metadata and cannot be proven safe (see inspectKustomizationNode) yields
// originUnavailable, so file attribution falls back to the directory.
func originModeFor(directory string) originPlan {
	safe, preserved, ownOrigins, walk := inspectKustomizationGraph(directory)
	if !safe {
		return originPlan{mode: originUnavailable}
	}
	slices.Sort(walk.allowedDirs)
	allowedRoots := slices.Compact(walk.allowedDirs)
	if ownOrigins {
		return originPlan{mode: originOwn, allowedRoots: allowedRoots, sources: walk.sources}
	}
	return originPlan{mode: originWrapper, preserved: preserved, allowedRoots: allowedRoots, sources: walk.sources}
}

// sameAs reports whether two inspections reached the same plan.
func (p originPlan) sameAs(other originPlan) bool {
	return p.mode == other.mode &&
		slices.Equal(p.preserved, other.preserved) &&
		slices.Equal(p.allowedRoots, other.allowedRoots) &&
		maps.Equal(p.sources, other.sources)
}

func inspectKustomizationGraph(directory string) (safe bool, preserved []string, ownOrigins bool, walk *originWalk) {
	file := selectedKustomizationFile(directory)
	if file == "" {
		return false, nil, false, nil
	}
	absFile, err := filepath.Abs(file)
	if err != nil {
		return false, nil, false, nil
	}

	walk = &originWalk{
		visited:     map[inspectKey]struct{}{},
		visiting:    map[inspectKey]struct{}{},
		allowedDirs: []string{filepath.Clean(directory)},
		sources:     map[string]string{},
	}
	safe, preserved, ownOrigins = walk.inspectKustomizationNode(absFile, filepath.Dir(absFile), true)
	if !safe {
		return false, nil, false, nil
	}
	return safe, preserved, ownOrigins, walk
}

// inspectKustomizationNode inspects the kustomization file and what it
// references. lexicalDir is the path Kustomize's origin annotations give the
// file's directory.
func (w *originWalk) inspectKustomizationNode(file, lexicalDir string, isRoot bool) (bool, []string, bool) {
	canonical, err := filepath.EvalSymlinks(file)
	if err != nil {
		return false, nil, false
	}
	loaderDir, err := filepath.EvalSymlinks(filepath.Dir(file))
	if err != nil {
		return false, nil, false
	}
	dir := loaderDir
	w.allowedDirs = append(w.allowedDirs, loaderDir, filepath.Dir(canonical))

	nodeKey := inspectKey{loaderDir: loaderDir, config: canonical}
	if _, inStack := w.visiting[nodeKey]; inStack {
		return false, nil, false
	}
	visitKey := inspectKey{loaderDir: loaderDir, config: canonical, lexicalDir: lexicalDir}
	if _, done := w.visited[visitKey]; done {
		return true, nil, false
	}
	w.visiting[nodeKey] = struct{}{}
	defer delete(w.visiting, nodeKey)
	// A generated resource's annotation names the kustomization file that
	// configured the generator.
	w.recordSource(filepath.Join(lexicalDir, filepath.Base(file)), canonical)

	contents, err := readKustomizationFile(canonical)
	if err != nil {
		return false, nil, false
	}
	var k types.Kustomization
	if err := k.Unmarshal(contents); err != nil {
		return false, nil, false
	}
	k.FixKustomization()

	var preserved []string
	var ownOrigins bool
	if isRoot {
		options := k.BuildMetadata
		if slices.Contains(options, types.OriginAnnotations) {
			ownOrigins = true
		} else {
			for _, option := range options {
				if option == types.ManagedByLabelOption {
					preserved = append(preserved, option)
				} else {
					return false, nil, false
				}
			}
		}
	}

	if len(k.Replacements) > 0 ||
		len(k.Transformers) > 0 ||
		len(k.Generators) > 0 ||
		len(k.Validators) > 0 ||
		len(k.Vars) > 0 || //nolint:staticcheck
		len(k.Configurations) > 0 ||
		len(k.Crds) > 0 ||
		len(k.OpenAPI) > 0 ||
		len(k.HelmCharts) > 0 {
		return false, nil, false
	}

	if k.CommonAnnotations != nil {
		if _, ok := k.CommonAnnotations[kustomizeOriginAnnotation]; ok {
			return false, nil, false
		}
	}

	if k.GeneratorOptions != nil && k.GeneratorOptions.Annotations != nil {
		if _, ok := k.GeneratorOptions.Annotations[kustomizeOriginAnnotation]; ok {
			return false, nil, false
		}
	}
	for _, gen := range k.ConfigMapGenerator {
		if gen.Options != nil && gen.Options.Annotations != nil {
			if _, ok := gen.Options.Annotations[kustomizeOriginAnnotation]; ok {
				return false, nil, false
			}
		}
	}
	for _, gen := range k.SecretGenerator {
		if gen.Options != nil && gen.Options.Annotations != nil {
			if _, ok := gen.Options.Annotations[kustomizeOriginAnnotation]; ok {
				return false, nil, false
			}
		}
	}

	for _, patch := range k.Patches {
		if !isPatchProvablySafe(dir, patch) {
			return false, nil, false
		}
	}
	for _, patch := range k.PatchesJson6902 { //nolint:staticcheck
		if !isPatchProvablySafe(dir, patch) {
			return false, nil, false
		}
	}
	for _, patch := range k.PatchesStrategicMerge { //nolint:staticcheck
		if !isPatchProvablySafe(dir, strategicMergeEntry(string(patch))) {
			return false, nil, false
		}
	}

	// Kustomize reads a resource, or a base, as a file before it tries it as a
	// directory or a Git repository. A component is always a directory.
	references := make([]string, 0, len(k.Resources)+len(k.Bases)+len(k.Components)) //nolint:staticcheck
	references = append(references, k.Resources...)
	references = append(references, k.Bases...) //nolint:staticcheck
	maybeFiles := len(references)
	references = append(references, k.Components...)

	for i, ref := range references {
		if ref == "" {
			continue
		}
		refPath := ref
		if !filepath.IsAbs(refPath) {
			refPath = filepath.Join(dir, refPath)
		}
		// A local file is read as one even when its name looks like Git
		// shorthand, as demo:v1.yaml does, provided Kustomize's accumulateFile
		// accepts it; otherwise accumulateResources falls back to loader.New.
		// Only a URL Kustomize fetches over HTTP is read from the network instead.
		if isRemoteReference(ref) {
			if i >= maybeFiles || isRemoteFile(ref) || !isKustomizeResourceFile(dir, refPath) {
				return false, nil, false
			}
		}
		refCanonical, err := filepath.EvalSymlinks(refPath)
		if err != nil {
			return false, nil, false
		}
		info, err := os.Stat(refCanonical)
		if err != nil {
			return false, nil, false
		}
		if info.IsDir() {
			// A referenced directory is trusted only if it is inspected too: it must
			// hold a kustomization that passes the same checks, and it becomes an
			// allowed origin root only because this walk visited it. References are
			// not confined to a project boundary: Kustomize builds them regardless,
			// so what matters for attribution is that every configuration that
			// shaped the output was inspected.
			childFile := selectedKustomizationFile(refCanonical)
			if childFile == "" {
				return false, nil, false
			}
			w.allowedDirs = append(w.allowedDirs, refCanonical)
			childSafe, _, _ := w.inspectKustomizationNode(childFile, filepath.Join(lexicalDir, ref), false)
			if !childSafe {
				return false, nil, false
			}
		} else if info.Mode().IsRegular() {
			if !pathcontainment.IsPathContained(dir, refCanonical) {
				return false, nil, false
			}
			if manifestHasOriginAnnotation(refCanonical) {
				return false, nil, false
			}
			w.recordSource(filepath.Join(lexicalDir, ref), refCanonical)
		} else {
			return false, nil, false
		}
	}

	w.visited[visitKey] = struct{}{}
	return true, preserved, ownOrigins
}

func manifestHasOriginAnnotation(file string) bool {
	bytesContent, err := readKustomizationFile(file)
	if err != nil {
		return true
	}
	docs, err := splitYAMLDocuments(bytesContent)
	if err != nil {
		return true
	}
	for _, doc := range docs {
		if len(bytes.TrimSpace(doc)) == 0 {
			continue
		}
		var parsed map[string]any
		if err := kyaml.Unmarshal(doc, &parsed); err != nil {
			return true
		}
		if objectHasOriginAnnotation(parsed) {
			return true
		}
	}
	return false
}

func objectHasOriginAnnotation(obj map[string]any) bool {
	if meta, ok := obj["metadata"].(map[string]any); ok {
		if annos, ok := meta["annotations"].(map[string]any); ok {
			if _, hasOrigin := annos[kustomizeOriginAnnotation]; hasOrigin {
				return true
			}
		}
	}
	if items, ok := obj["items"].([]any); ok {
		for _, item := range items {
			if itemMap, ok := item.(map[string]any); ok {
				if objectHasOriginAnnotation(itemMap) {
					return true
				}
			}
		}
	}
	return false
}

func isRemoteReference(ref string) bool {
	if strings.Contains(ref, "://") ||
		strings.HasPrefix(ref, "git::") ||
		strings.HasPrefix(ref, "git@") ||
		strings.Contains(ref, "?ref=") ||
		strings.Contains(ref, "?version=") ||
		strings.Contains(ref, "?submodules=") ||
		strings.Contains(ref, ".git//") ||
		strings.HasSuffix(ref, ".git") ||
		strings.Contains(ref, ".git?") {
		return true
	}
	lower := strings.ToLower(ref)
	if strings.HasPrefix(lower, "github.com/") ||
		strings.HasPrefix(lower, "gitlab.com/") ||
		strings.HasPrefix(lower, "bitbucket.org/") ||
		strings.HasPrefix(lower, "dev.azure.com/") ||
		strings.HasPrefix(lower, "source.developers.google.com/") {
		return true
	}
	if strings.Contains(ref, "@") && strings.Contains(ref, ":") {
		return true
	}
	// Kustomize tries Git before a local directory and accepts scp-like and
	// shorthand forms (git@host:org/repo, github.com:org/repo, gh:org/repo).
	// No trusted local path contains a colon.
	if strings.Contains(ref, ":") && (!filepath.IsAbs(ref) || len(ref) < 2 || ref[1] != ':') {
		return true
	}
	return false
}

// isRemoteFile reports whether Kustomize fetches path over HTTP rather than
// reading it from disk. It is the test Kustomize's file loader makes.
func isRemoteFile(path string) bool {
	u, err := url.Parse(path)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https")
}

// isKustomizeResourceFile reports whether Kustomize's accumulateFile accepts
// path under dir as a local resource file. When accumulateFile fails,
// accumulateResources falls back to loader.New (base directory or Git repo).
func isKustomizeResourceFile(dir, path string) bool {
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || !pathcontainment.IsPathContained(dir, canonical) {
		return false
	}
	info, err := os.Stat(canonical)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	content, err := readKustomizationFile(canonical)
	if err != nil {
		return false
	}
	_, err = resmap.NewFactory(provider.NewDepProvider().GetResourceFactory()).NewResMapFromBytes(content)
	return err == nil
}

// strategicMergeEntry is the patch a patchesStrategicMerge entry stands for.
// Kustomize first parses the entry itself as resources and only reads it as a
// path when that fails, so a patch written on one line is content, not a file
// name. The same parser decides here.
func strategicMergeEntry(entry string) types.Patch {
	if _, err := provider.NewDepProvider().GetResourceFactory().SliceFromBytes([]byte(entry)); err == nil {
		return types.Patch{Patch: entry}
	}
	return types.Patch{Path: entry}
}

func isPatchProvablySafe(baseDir string, patch types.Patch) bool {
	if patch.Target != nil {
		if patch.Target.AnnotationSelector != "" || patch.Target.LabelSelector != "" {
			return false
		}
	}
	if patch.Options != nil && (patch.Options.AllowNameChange || patch.Options.AllowKindChange) {
		return false
	}

	content := patch.Patch
	if patch.Path != "" {
		// A patch path is always a file, so Git shorthand does not apply to it.
		if isRemoteFile(patch.Path) {
			return false
		}
		patchFilePath := patch.Path
		if !filepath.IsAbs(patchFilePath) {
			patchFilePath = filepath.Join(baseDir, patchFilePath)
		}
		cleanPath := filepath.Clean(patchFilePath)
		canonPatch, err := filepath.EvalSymlinks(cleanPath)
		if err != nil {
			return false
		}
		if !pathcontainment.IsPathContained(baseDir, canonPatch) {
			return false
		}
		bytesContent, err := readKustomizationFile(canonPatch)
		if err != nil {
			return false
		}
		content = string(bytesContent)
	}

	content = strings.TrimSpace(content)
	if content == "" {
		return false
	}

	docs, err := splitYAMLDocuments([]byte(content))
	if err != nil || len(docs) == 0 {
		return false
	}

	for _, doc := range docs {
		if len(bytes.TrimSpace(doc)) == 0 {
			continue
		}
		if !isPatchDocumentProvablySafe(doc) {
			return false
		}
	}

	return true
}

func isPatchDocumentProvablySafe(doc []byte) bool {
	docStr := strings.TrimSpace(string(doc))
	if docStr == "" {
		return true
	}

	var ops []map[string]any
	if err := kyaml.Unmarshal(doc, &ops); err == nil && len(ops) > 0 {
		for _, op := range ops {
			for key := range op {
				switch strings.ToLower(key) {
				case "op", "path", "from", "value":
					if key != strings.ToLower(key) {
						return false // Kustomize reads exact keys; case-differing keys are ambiguous
					}
				}
			}
			opName, _ := op["op"].(string)
			switch opName {
			case "add", "replace", "remove":
			default:
				return false
			}
			if from, _ := op["from"].(string); from != "" {
				return false
			}
			opPath, _ := op["path"].(string)
			if !strings.HasPrefix(opPath, "/spec/") {
				return false
			}
		}
		return true
	}

	var smp map[string]any
	if err := kyaml.Unmarshal(doc, &smp); err == nil && len(smp) > 0 {
		if _, hasDelete := smp["$patch"]; hasDelete {
			return false
		}
		for key, val := range smp {
			switch key {
			case "apiVersion", "kind":
			case "metadata":
				meta, ok := val.(map[string]any)
				if !ok {
					return false
				}
				for mKey := range meta {
					if mKey != "name" && mKey != "namespace" {
						return false
					}
				}
			case "spec":
			default:
				return false
			}
		}
		return true
	}

	return false
}

// originRenderer is renderWithOrigins, as a variable so a test can make it fail
// and check that the scan falls back to the plain build.
var originRenderer = renderWithOrigins

// renderWithOrigins renders directory like a plain build does, through a
// temporary kustomization that references it and turns origin annotations on,
// next to the buildMetadata the scanned kustomization asked for. Kustomize
// passes the setting down to every kustomization the directory pulls in, so each
// resource comes out annotated with the file it was read from, and the scanned
// directory is never touched.
//
// It returns the rendered YAML and the directory the origin paths are relative
// to. It reports false when it cannot render this way, for example when no
// relative path leads from the temporary directory to the scanned one (on
// Windows, a different drive), and the caller then does the plain build as
// before. A failure here must never make a scan worse than it was.
func renderWithOrigins(newKustomizer func() *krusty.Kustomizer, directory string, preserved []string) ([]byte, string, bool) {
	wrapperDir, err := os.MkdirTemp("", "kubescape-kustomize-origin-")
	if err != nil {
		return nil, "", false
	}
	defer func() { _ = os.RemoveAll(wrapperDir) }()
	// Kustomize resolves the wrapper's directory before it follows the
	// reference, so the reference has to start from the resolved directory. On
	// macOS the temporary directory is under /var, a link to /private/var, and a
	// reference from the unresolved one climbs a level too few.
	if resolved, err := filepath.EvalSymlinks(wrapperDir); err == nil {
		wrapperDir = resolved
	}

	reference, err := filepath.Rel(wrapperDir, directory)
	if err != nil {
		return nil, "", false
	}
	// Kustomize refuses an absolute directory as a resource, so the reference is
	// relative. A JSON value is also valid YAML, which keeps any character in the
	// path from being read as YAML syntax.
	quoted, err := json.Marshal(filepath.ToSlash(reference))
	if err != nil {
		return nil, "", false
	}
	metadata := slices.Clone(preserved)
	if !slices.Contains(metadata, types.OriginAnnotations) {
		metadata = append(metadata, types.OriginAnnotations)
	}
	options, err := json.Marshal(metadata)
	if err != nil {
		return nil, "", false
	}
	kustomization := "resources:\n- " + string(quoted) + "\nbuildMetadata: " + string(options) + "\n"
	if err := os.WriteFile(filepath.Join(wrapperDir, "kustomization.yaml"), []byte(kustomization), 0o600); err != nil {
		return nil, "", false
	}

	fSys := &kustomizeHelmFileSystem{FileSystem: &boundedOnDiskFileSystem{FileSystem: filesys.MakeFsOnDisk()}}
	resMap, err := newKustomizer().Run(fSys, wrapperDir)
	if err != nil || fSys.recordedValidationErr() != nil {
		return nil, "", false
	}
	yml, err := resMap.AsYaml()
	if err != nil {
		return nil, "", false
	}
	return yml, wrapperDir, true
}

// originFilesFor returns, for each of the plain build's resources in order, the
// local file it was read from, with "" where that is not known. It returns nil
// when nothing can be attributed.
//
// The plain build stays the authority on what a resource is. The wrapper's build
// is a different build: its annotations are present while Kustomize runs the
// transformers, so a patch that selects on them, such as
// annotationSelector: "!config.kubernetes.io/origin", selects different
// resources, and removing the annotation afterwards cannot undo that. So the
// wrapper's output is used for the file names only, and only if, with the
// annotation removed, it is the same as the plain build's resource for resource.
// Otherwise nothing is attributed and the resources are reported against their
// directory, exactly as the plain build alone would have.
func originFilesFor(newKustomizer func() *krusty.Kustomizer, directory string, plan originPlan, plain []workloadinterface.IMetadata) []string {
	switch plan.mode {
	case originOwn:
		// The kustomization asked for origin annotations, so the plain build
		// carries them, relative to the directory. They stay where they are.
		files := make([]string, len(plain))
		for i := range plain {
			files[i] = plan.originFile(plain[i].GetObject(), directory, false)
		}
		return files
	case originWrapper:
		return wrapperOriginFiles(newKustomizer, directory, plan, plain)
	}
	return nil
}

// wrapperOriginFiles is originFilesFor for a kustomization that did not ask for
// origin annotations: render it through the wrapper, take the files from there,
// and trust them only if the wrapper rendered the same resources.
func wrapperOriginFiles(newKustomizer func() *krusty.Kustomizer, directory string, plan originPlan, plain []workloadinterface.IMetadata) []string {
	rendered, base, ok := originRenderer(newKustomizer, directory, plan.preserved)
	if !ok {
		return nil
	}
	annotated, err := ReadFile(rendered, YAML_FILE_FORMAT)
	if err != nil || len(annotated) != len(plain) {
		return nil
	}
	files := make([]string, len(annotated))
	for i := range annotated {
		files[i] = plan.originFile(annotated[i].GetObject(), base, true)
		if !reflect.DeepEqual(annotated[i].GetObject(), plain[i].GetObject()) {
			return nil
		}
	}
	return files
}

// takeKustomizeOrigin returns the local file that Kustomize's origin annotation
// on obj names. With remove set it also takes the annotation off obj, so that no
// rule, report or fix sees an annotation the user did not ask for; without it
// the annotation stays, for a kustomization that asked for it. It returns ""
// when the annotation is absent, names a remote repository, or names a file that
// is not there: Kubescape would rather point at the directory than at a file that
// is not the source.
//
// baseDir is the directory the annotation's path is relative to.
// allowedRoots are the directory roots that the resolved file must be contained within.
// If allowedRoots is empty, baseDir is used as the single allowed root.
func takeKustomizeOrigin(obj map[string]any, baseDir string, remove bool, allowedRoots ...string) string {
	relative := takeOriginPath(obj, remove)
	if relative == "" {
		return ""
	}
	return localOriginFile(baseDir, relative, allowedRoots)
}

// originFile is takeKustomizeOrigin for a resource of this plan's build. On
// top of its checks, the file has to be the one Kustomize read: the annotation
// is text, and the file it names can be another one, or none (see
// originWalk.sources). When the walk knows the file Kustomize read instead, that
// file is returned. When it does not, nothing is.
func (p originPlan) originFile(obj map[string]any, baseDir string, remove bool) string {
	relative := takeOriginPath(obj, remove)
	if relative == "" {
		return ""
	}
	named, err := filepath.Abs(filepath.Join(baseDir, filepath.FromSlash(relative)))
	if err != nil {
		return ""
	}
	read := p.sources[named]
	if read == "" {
		return ""
	}
	// The name the annotation gives is kept when it is the file, so a file
	// reached through a link is reported under the name the repository shows.
	if file := localOriginFile(baseDir, relative, p.allowedRoots); file != "" && isSameFile(file, read) {
		return file
	}
	if isContainedInAny(read, p.allowedRoots) {
		return read
	}
	return ""
}

func isSameFile(a, b string) bool {
	infoA, err := os.Stat(a)
	if err != nil {
		return false
	}
	infoB, err := os.Stat(b)
	return err == nil && os.SameFile(infoA, infoB)
}

func isContainedInAny(file string, roots []string) bool {
	for _, root := range roots {
		if root != "" && pathcontainment.IsPathContained(root, file) {
			return true
		}
	}
	return false
}

// takeOriginPath returns the local path Kustomize's origin annotation on obj
// names, relative to the directory the build started in, or "" when there is
// none. With remove set it also takes the annotation off obj.
func takeOriginPath(obj map[string]any, remove bool) string {
	metadata, _ := obj["metadata"].(map[string]any)
	annotations, _ := metadata["annotations"].(map[string]any)
	raw, ok := annotations[kustomizeOriginAnnotation].(string)
	if !ok {
		return ""
	}
	if remove {
		delete(annotations, kustomizeOriginAnnotation)
		if len(annotations) == 0 {
			delete(metadata, "annotations")
		}
	}

	var origin kustomizeOrigin
	if err := kyaml.Unmarshal([]byte(raw), &origin); err != nil || origin.Repo != "" {
		return ""
	}
	if origin.Path != "" {
		return origin.Path
	}
	return origin.ConfiguredIn
}

// localOriginFile returns the file relative names under baseDir, when it is a
// regular file inside one of allowedRoots, or baseDir if there are none.
func localOriginFile(baseDir, relative string, allowedRoots []string) string {
	file := filepath.Clean(filepath.Join(baseDir, filepath.FromSlash(relative)))
	canonFile, err := filepath.EvalSymlinks(file)
	if err != nil {
		return ""
	}
	info, err := os.Stat(canonFile)
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}

	roots := allowedRoots
	if len(roots) == 0 {
		roots = []string{baseDir}
	}
	if !isContainedInAny(canonFile, roots) {
		return ""
	}
	return file
}
