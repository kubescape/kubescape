package cautils

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"

	"sigs.k8s.io/kustomize/api/krusty"
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
}

// originModeFor reads the scanned kustomization's buildMetadata and decides how
// its resources' origin can be learned. Kustomize hands the outermost
// kustomization's buildMetadata to every kustomization below it, so a wrapper
// that set its own list would replace the scanned one.
//
//   - Nothing requested: use the wrapper.
//   - Only managedByLabel: use the wrapper and repeat the option, so the label is
//     still added.
//   - originAnnotations requested: the plain build already records the origin.
//   - Anything else, transformerAnnotations in particular: no wrapper. Its
//     annotation holds paths that are relative to the build's root, which the
//     wrapper changes, so the wrapper would hand a rule different input.
func originModeFor(directory string) originPlan {
	file := selectedKustomizationFile(directory)
	if file == "" {
		return originPlan{mode: originUnavailable}
	}
	contents, err := readKustomizationFile(file)
	if err != nil {
		return originPlan{mode: originUnavailable}
	}
	var kustomization types.Kustomization
	if err := kustomization.Unmarshal(contents); err != nil {
		return originPlan{mode: originUnavailable}
	}

	options := kustomization.BuildMetadata
	switch {
	case len(options) == 0:
		return originPlan{mode: originWrapper}
	case slices.Contains(options, types.OriginAnnotations):
		return originPlan{mode: originOwn}
	}
	for _, option := range options {
		if option != types.ManagedByLabelOption {
			return originPlan{mode: originUnavailable}
		}
	}
	return originPlan{mode: originWrapper, preserved: slices.Clone(options)}
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

	resMap, err := newKustomizer().Run(filesys.MakeFsOnDisk(), wrapperDir)
	if err != nil {
		return nil, "", false
	}
	yml, err := resMap.AsYaml()
	if err != nil {
		return nil, "", false
	}
	return yml, wrapperDir, true
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
func takeKustomizeOrigin(obj map[string]any, baseDir string, remove bool) string {
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
	relative := origin.Path
	if relative == "" {
		relative = origin.ConfiguredIn
	}
	if relative == "" {
		return ""
	}

	file := filepath.Clean(filepath.Join(baseDir, filepath.FromSlash(relative)))
	info, err := os.Stat(file)
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	return file
}
