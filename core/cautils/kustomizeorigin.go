package cautils

import (
	"encoding/json"
	"os"
	"path/filepath"

	"sigs.k8s.io/kustomize/api/krusty"
	"sigs.k8s.io/kustomize/kyaml/filesys"
	kyaml "sigs.k8s.io/kustomize/kyaml/yaml"
)

// Kustomize writes the file a resource came from into this annotation when the
// kustomization asks for it with buildMetadata: [originAnnotations]. The scanned
// repository's own kustomization does not ask, so Kubescape asks on its behalf
// through a wrapper (see renderWithOrigins) and removes the annotation again
// before the resource goes anywhere else.
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

// originRenderer is renderWithOrigins, as a variable so a test can make it fail
// and check that the scan falls back to the plain build.
var originRenderer = renderWithOrigins

// renderWithOrigins renders directory like a plain build does, through a
// temporary kustomization that references it and turns origin annotations on.
// Kustomize passes the setting down to every kustomization the directory pulls
// in, so each resource comes out annotated with the file it was read from, and
// the scanned directory is never touched.
//
// It returns the rendered YAML and the directory the origin paths are relative
// to. It reports false when it cannot render this way, for example when no
// relative path leads from the temporary directory to the scanned one (on
// Windows, a different drive), and the caller then does the plain build as
// before. A failure here must never make a scan worse than it was.
func renderWithOrigins(newKustomizer func() *krusty.Kustomizer, directory string) ([]byte, string, bool) {
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
	// relative. A JSON string is also a valid YAML string, which keeps any
	// character in the path from being read as YAML syntax.
	quoted, err := json.Marshal(filepath.ToSlash(reference))
	if err != nil {
		return nil, "", false
	}
	kustomization := "resources:\n- " + string(quoted) + "\nbuildMetadata:\n- originAnnotations\n"
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

// takeKustomizeOrigin removes Kustomize's origin annotation from obj, so that no
// rule, report or fix ever sees an annotation the user did not write, and
// returns the local file it named. It returns "" when the annotation is absent,
// names a remote repository, or names a file that is not there: Kubescape would
// rather point at the directory than at a file that is not the source.
//
// baseDir is the directory the annotation's path is relative to.
func takeKustomizeOrigin(obj map[string]any, baseDir string) string {
	metadata, _ := obj["metadata"].(map[string]any)
	annotations, _ := metadata["annotations"].(map[string]any)
	raw, ok := annotations[kustomizeOriginAnnotation].(string)
	if !ok {
		return ""
	}
	delete(annotations, kustomizeOriginAnnotation)
	if len(annotations) == 0 {
		delete(metadata, "annotations")
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
