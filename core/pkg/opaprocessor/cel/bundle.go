package cel

import (
	"fmt"
	"strings"
)

// policyConfigDefinitionFile holds the ControlConfiguration CRD the params
// objects are instances of. The engine never reads it (it consumes the params
// values, not their schema), but a cluster needs the CRD before the
// configuration can be applied, so it ships in the deployable stream.
const policyConfigDefinitionFile = "policy-configuration-definition.yaml"

// deployFiles are the bundle files that make up the deployable library, in
// apply order: the CRD first, then the configuration instance, then the
// policies that reference it.
var deployFiles = []string{
	policyConfigDefinitionFile,
	controlConfigFile,
	vapBundleFile,
}

// EmbeddedLibraryYAML returns the vendored cel-admission-library bundle as one
// multi-document YAML stream ready for kubectl apply. This is the same embedded
// copy the scan engine evaluates and create-policy-binding resolves metadata
// from, so what a user deploys is exactly what this build was tested against —
// deploying anything else (e.g. a fresher upstream release) would let admission
// and offline scans disagree about the same object (issue #2507).
func EmbeddedLibraryYAML() (string, error) {
	parts := make([]string, 0, len(deployFiles))
	for _, name := range deployFiles {
		data, err := vapdataFS.ReadFile(vapdataDir + "/" + name)
		if err != nil {
			return "", fmt.Errorf("read embedded %s: %w", name, err)
		}
		parts = append(parts, string(data))
	}
	return strings.Join(parts, "\n---\n") + "\n", nil
}
