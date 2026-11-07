package fixhandler

import "fmt"

// manifestDocument pairs an editor's document with its position in the source.
type manifestDocument struct {
	sourceIndex int
	identity    manifestIdentity
}

type manifestIdentity struct {
	apiVersion, kind, namespace, name string
}

func manifestIdentityOf(obj map[string]any) manifestIdentity {
	var id manifestIdentity
	id.apiVersion, _ = obj["apiVersion"].(string)
	id.kind, _ = obj["kind"].(string)
	meta, _ := obj["metadata"].(map[string]any)
	id.name, _ = meta["name"].(string)
	if namespace := meta["namespace"]; namespace != nil {
		var ok bool
		id.namespace, ok = namespace.(string)
		if !ok {
			return manifestIdentity{}
		}
	}
	return id
}

// verifyFixTargets checks the document indices used by the editor, before
// applying any changes to the file. A moved resource requires a fresh scan.
func verifyFixTargets(fixes []ResourceFixInfo, documents []manifestDocument) error {
	counts := make(map[manifestIdentity]int, len(documents))
	for _, doc := range documents {
		counts[doc.identity]++
	}

	for _, fix := range fixes {
		index := fix.DocumentIndex
		var expected manifestIdentity
		if fix.Resource != nil {
			expected = manifestIdentityOf(fix.Resource.GetObject())
		}
		if expected.apiVersion == "" || expected.kind == "" || expected.name == "" {
			return fmt.Errorf("cannot verify resource identity at document index %d from the scan report; re-scan and use the new report", index)
		}
		if index < 0 || index >= len(documents) || documents[index].identity != expected {
			return fmt.Errorf("document index %d no longer matches the scan report (expected kind %q, name %q, apiVersion %q, namespace %q); re-scan and use the new report",
				index, expected.kind, expected.name, expected.apiVersion, expected.namespace)
		}
		if counts[expected] > 1 {
			return fmt.Errorf("resource %q at document index %d has a duplicate identity in the manifest; remove the duplicate, then re-scan and use the new report", expected.name, index)
		}
	}
	return nil
}
