package reportcrypto

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/reporthandling"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

// rawObject keeps report fields as raw JSON so decrypting a report does not
// discard fields introduced by a newer Kubescape or backend version.
type rawObject map[string]json.RawMessage

// reportDecryptor owns the data-encryption key and the relationship between
// encrypted resource IDs and the IDs reconstructed from decrypted resources.
// A single instance is used for the complete report so every cross-reference
// is rewritten consistently.
type reportDecryptor struct {
	dek       []byte
	idMapping map[string]string
	masterKey []byte
	report    rawObject
}

// DecryptReport restores all fields encrypted by anonymizer.ApplyEncrypted.
//
// The operation is transactional from the caller's perspective. The input is
// parsed and transformed entirely in memory, and bytes are returned only when
// every encrypted field has been restored successfully. JSON fields unknown to
// this Kubescape version are preserved.
func DecryptReport(data, masterKey []byte) ([]byte, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("report is empty")
	}

	report, err := decodeObject(data, "report")
	if err != nil {
		return nil, err
	}

	decryptor := &reportDecryptor{
		idMapping: make(map[string]string),
		masterKey: masterKey,
		report:    report,
	}
	defer func() {
		zeroBytes(decryptor.dek)
	}()

	if err := decryptor.decryptMetadata(); err != nil {
		return nil, err
	}

	if err := decryptor.decryptResources(); err != nil {
		return nil, err
	}

	if err := decryptor.decryptResults(); err != nil {
		return nil, err
	}

	if err := decryptor.decryptResourceLabels(); err != nil {
		return nil, err
	}

	decrypted, err := json.MarshalIndent(decryptor.report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal decrypted report: %w", err)
	}

	return decrypted, nil
}

// DecryptReportFromEnv restores a report using KUBESCAPE_MASTER_KEY.
func DecryptReportFromEnv(data []byte) ([]byte, error) {
	masterKey, err := GetMasterKeyFromEnv("decryption")
	if err != nil {
		return nil, err
	}

	defer zeroBytes(masterKey)

	return DecryptReport(data, masterKey)
}

func (d *reportDecryptor) decryptMetadata() error {
	metadataRaw, ok := d.report["metadata"]
	if !ok || isJSONNull(metadataRaw) {
		return fmt.Errorf("report metadata not found")
	}

	var metadata reporthandlingv2.Metadata
	if err := json.Unmarshal(metadataRaw, &metadata); err != nil {
		return fmt.Errorf("failed to parse metadata: %w", err)
	}

	dek, err := DEKFromMetadata(&metadata, d.masterKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt report data key: %w", err)
	}
	d.dek = dek

	if err := decryptRepoContextMetadata(&metadata, d.dek); err != nil {
		return fmt.Errorf("failed to decrypt report metadata: %w", err)
	}

	// Marshal the known metadata shape, then recursively merge it into the
	// original raw object. This updates decrypted values while retaining fields
	// from future report schemas, including unknown fields inside lastCommit.
	knownMetadata, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	original, err := decodeObject(metadataRaw, "metadata")
	if err != nil {
		return err
	}
	known, err := decodeObject(knownMetadata, "metadata")
	if err != nil {
		return err
	}

	merged, err := mergeKnownObject(original, known, "metadata")
	if err != nil {
		return err
	}

	d.report["metadata"], err = json.Marshal(merged)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	return nil
}

func (d *reportDecryptor) decryptResources() error {
	resourcesRaw, ok := d.report["resources"]
	if !ok || isJSONNull(resourcesRaw) {
		return nil
	}

	resources, err := decodeObjectArray(resourcesRaw, "resources")
	if err != nil {
		return err
	}

	for i := range resources {
		context := fmt.Sprintf("resources[%d]", i)
		oldID, newID, err := d.decryptResource(resources[i], context)
		if err != nil {
			return err
		}

		if err := d.recordResourceID(oldID, newID, context); err != nil {
			return err
		}
	}

	d.report["resources"], err = json.Marshal(resources)
	if err != nil {
		return fmt.Errorf("failed to marshal resources: %w", err)
	}

	return nil
}

func (d *reportDecryptor) decryptResults() error {
	resultsRaw, ok := d.report["results"]
	if !ok || isJSONNull(resultsRaw) {
		return nil
	}

	results, err := decodeObjectArray(resultsRaw, "results")
	if err != nil {
		return err
	}

	// Raw resources may be the only resource copies in reports emitted by the
	// chunked reporter. Decrypt them first so their IDs are available when all
	// result references are remapped in the second pass.
	for i := range results {
		context := fmt.Sprintf("results[%d].rawResource", i)
		rawResource, ok, err := optionalObject(results[i], "rawResource", context)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}

		oldID, newID, err := d.decryptResource(rawResource, context)
		if err != nil {
			return err
		}
		if err := d.recordResourceID(oldID, newID, context); err != nil {
			return err
		}

		results[i]["rawResource"], err = json.Marshal(rawResource)
		if err != nil {
			return fmt.Errorf("failed to marshal %s: %w", context, err)
		}
	}

	for i := range results {
		if err := d.remapResult(results[i], i); err != nil {
			return err
		}
	}

	d.report["results"], err = json.Marshal(results)
	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}

	return nil
}

func (d *reportDecryptor) decryptResource(resource rawObject, context string) (string, string, error) {
	oldID, _, err := optionalString(resource, "resourceID", context+".resourceID")
	if err != nil {
		return "", "", err
	}

	objectRaw, hasObject := resource["object"]
	if !hasObject || isJSONNull(objectRaw) {
		if err := d.decryptSource(resource, context); err != nil {
			return "", "", err
		}
		return oldID, d.remapResourceID(oldID), nil
	}

	workload, err := workloadinterface.NewWorkload(objectRaw)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse %s.object: %w", context, err)
	}

	if err := DecryptResourceMetadata(workload, d.dek); err != nil {
		return "", "", fmt.Errorf("failed to decrypt %s metadata: %w", context, err)
	}
	if err := DecryptResourceLabels(workload, d.dek); err != nil {
		return "", "", fmt.Errorf("failed to decrypt %s labels: %w", context, err)
	}
	if err := DecryptResourceAnnotations(workload, d.dek); err != nil {
		return "", "", fmt.Errorf("failed to decrypt %s annotations: %w", context, err)
	}
	if err := DecryptResourceObjectSourcePath(workload, d.dek); err != nil {
		return "", "", fmt.Errorf("failed to decrypt %s sourcePath: %w", context, err)
	}
	if err := DecryptContainerMetadata(workload, d.dek); err != nil {
		return "", "", fmt.Errorf("failed to decrypt %s containers: %w", context, err)
	}

	newID := workload.GetID()
	updatedObject, err := json.Marshal(workload.GetWorkload())
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal %s.object: %w", context, err)
	}
	resource["object"] = updatedObject

	if oldID != "" || newID != "" {
		resource["resourceID"], err = json.Marshal(newID)
		if err != nil {
			return "", "", fmt.Errorf("failed to marshal %s.resourceID: %w", context, err)
		}
	}

	if err := d.decryptSource(resource, context); err != nil {
		return "", "", err
	}

	return oldID, newID, nil
}

func (d *reportDecryptor) decryptSource(resource rawObject, context string) error {
	sourceRaw, ok := resource["source"]
	if !ok || isJSONNull(sourceRaw) {
		return nil
	}

	var source reporthandling.Source
	if err := json.Unmarshal(sourceRaw, &source); err != nil {
		return fmt.Errorf("failed to parse %s.source: %w", context, err)
	}
	if err := DecryptResourceSource(&source, d.dek); err != nil {
		return fmt.Errorf("failed to decrypt %s.source: %w", context, err)
	}

	knownSource, err := json.Marshal(source)
	if err != nil {
		return fmt.Errorf("failed to marshal %s.source: %w", context, err)
	}
	original, err := decodeObject(sourceRaw, context+".source")
	if err != nil {
		return err
	}
	known, err := decodeObject(knownSource, context+".source")
	if err != nil {
		return err
	}
	merged, err := mergeKnownObject(original, known, context+".source")
	if err != nil {
		return err
	}

	resource["source"], err = json.Marshal(merged)
	if err != nil {
		return fmt.Errorf("failed to marshal %s.source: %w", context, err)
	}

	return nil
}

func (d *reportDecryptor) recordResourceID(oldID, newID, context string) error {
	if oldID == "" || newID == "" || oldID == newID {
		return nil
	}

	if existing, ok := d.idMapping[oldID]; ok && existing != newID {
		return fmt.Errorf("%s maps resource ID %q to %q, already mapped to %q", context, oldID, newID, existing)
	}
	d.idMapping[oldID] = newID
	return nil
}

func (d *reportDecryptor) remapResult(result rawObject, resultIndex int) error {
	context := fmt.Sprintf("results[%d]", resultIndex)
	if err := d.remapStringField(result, "resourceID", context+".resourceID"); err != nil {
		return err
	}

	prioritized, ok, err := optionalObject(result, "prioritizedResource", context+".prioritizedResource")
	if err != nil {
		return err
	}
	if ok {
		if err := d.remapStringField(prioritized, "resourceID", context+".prioritizedResource.resourceID"); err != nil {
			return err
		}
		result["prioritizedResource"], err = json.Marshal(prioritized)
		if err != nil {
			return fmt.Errorf("failed to marshal %s.prioritizedResource: %w", context, err)
		}
	}

	rawResource, ok, err := optionalObject(result, "rawResource", context+".rawResource")
	if err != nil {
		return err
	}
	if ok {
		if err := d.remapStringField(rawResource, "resourceID", context+".rawResource.resourceID"); err != nil {
			return err
		}
		result["rawResource"], err = json.Marshal(rawResource)
		if err != nil {
			return fmt.Errorf("failed to marshal %s.rawResource: %w", context, err)
		}
	}

	controlsRaw, ok := result["controls"]
	if !ok || isJSONNull(controlsRaw) {
		return nil
	}
	controls, err := decodeObjectArray(controlsRaw, context+".controls")
	if err != nil {
		return err
	}

	for controlIndex := range controls {
		controlContext := fmt.Sprintf("%s.controls[%d]", context, controlIndex)
		rulesRaw, ok := controls[controlIndex]["rules"]
		if !ok || isJSONNull(rulesRaw) {
			continue
		}
		rules, err := decodeObjectArray(rulesRaw, controlContext+".rules")
		if err != nil {
			return err
		}

		for ruleIndex := range rules {
			ruleContext := fmt.Sprintf("%s.rules[%d]", controlContext, ruleIndex)
			if err := d.remapRule(rules[ruleIndex], ruleContext); err != nil {
				return err
			}
		}

		controls[controlIndex]["rules"], err = json.Marshal(rules)
		if err != nil {
			return fmt.Errorf("failed to marshal %s.rules: %w", controlContext, err)
		}
	}

	result["controls"], err = json.Marshal(controls)
	if err != nil {
		return fmt.Errorf("failed to marshal %s.controls: %w", context, err)
	}

	return nil
}

func (d *reportDecryptor) remapRule(rule rawObject, context string) error {
	pathsRaw, ok := rule["paths"]
	if ok && !isJSONNull(pathsRaw) {
		paths, err := decodeObjectArray(pathsRaw, context+".paths")
		if err != nil {
			return err
		}
		for pathIndex := range paths {
			pathContext := fmt.Sprintf("%s.paths[%d].resourceID", context, pathIndex)
			if err := d.remapStringField(paths[pathIndex], "resourceID", pathContext); err != nil {
				return err
			}
		}
		rule["paths"], err = json.Marshal(paths)
		if err != nil {
			return fmt.Errorf("failed to marshal %s.paths: %w", context, err)
		}
	}

	relatedRaw, ok := rule["relatedResourcesIDs"]
	if !ok || isJSONNull(relatedRaw) {
		return nil
	}
	var related []string
	if err := json.Unmarshal(relatedRaw, &related); err != nil {
		return fmt.Errorf("failed to parse %s.relatedResourcesIDs: %w", context, err)
	}
	for i := range related {
		related[i] = d.remapResourceID(related[i])
	}
	updatedRelated, err := json.Marshal(related)
	if err != nil {
		return fmt.Errorf("failed to marshal %s.relatedResourcesIDs: %w", context, err)
	}
	rule["relatedResourcesIDs"] = updatedRelated

	return nil
}

func (d *reportDecryptor) decryptResourceLabels() error {
	labelsRaw, ok := d.report["resourceLabels"]
	if !ok || isJSONNull(labelsRaw) {
		return nil
	}

	labelsByResource, err := decodeObject(labelsRaw, "resourceLabels")
	if err != nil {
		return err
	}
	decryptedLabels := make(rawObject, len(labelsByResource))

	for oldID, rawLabels := range labelsByResource {
		context := fmt.Sprintf("resourceLabels[%q]", oldID)
		labels, err := decodeObject(rawLabels, context)
		if err != nil {
			return err
		}

		for key, rawValue := range labels {
			if isJSONNull(rawValue) {
				continue
			}
			var value string
			if err := json.Unmarshal(rawValue, &value); err != nil {
				return fmt.Errorf("failed to parse %s[%q]: %w", context, key, err)
			}
			value, err = decryptIfEncrypted(value, d.dek)
			if err != nil {
				return fmt.Errorf("failed to decrypt %s[%q]: %w", context, key, err)
			}
			labels[key], err = json.Marshal(value)
			if err != nil {
				return fmt.Errorf("failed to marshal %s[%q]: %w", context, key, err)
			}
		}

		newID := d.remapResourceID(oldID)
		if existingRaw, exists := decryptedLabels[newID]; exists {
			existing, err := decodeObject(existingRaw, fmt.Sprintf("resourceLabels[%q]", newID))
			if err != nil {
				return err
			}
			for key, value := range labels {
				if existingValue, ok := existing[key]; ok && !bytes.Equal(existingValue, value) {
					return fmt.Errorf("resourceLabels entries restored to resource ID %q with conflicting value for label %q", newID, key)
				}
				existing[key] = value
			}
			labels = existing
		}
		decryptedLabels[newID], err = json.Marshal(labels)
		if err != nil {
			return fmt.Errorf("failed to marshal %s: %w", context, err)
		}
	}

	d.report["resourceLabels"], err = json.Marshal(decryptedLabels)
	if err != nil {
		return fmt.Errorf("failed to marshal resourceLabels: %w", err)
	}

	return nil
}

func (d *reportDecryptor) remapStringField(object rawObject, field, context string) error {
	value, ok, err := optionalString(object, field, context)
	if err != nil || !ok {
		return err
	}
	object[field], err = json.Marshal(d.remapResourceID(value))
	if err != nil {
		return fmt.Errorf("failed to marshal %s: %w", context, err)
	}
	return nil
}

func (d *reportDecryptor) remapResourceID(id string) string {
	if mapped, ok := d.idMapping[id]; ok {
		return mapped
	}
	return id
}

func optionalString(object rawObject, field, context string) (string, bool, error) {
	raw, ok := object[field]
	if !ok || isJSONNull(raw) {
		return "", false, nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false, fmt.Errorf("failed to parse %s: %w", context, err)
	}
	return value, true, nil
}

func optionalObject(parent rawObject, field, context string) (rawObject, bool, error) {
	raw, ok := parent[field]
	if !ok || isJSONNull(raw) {
		return nil, false, nil
	}
	object, err := decodeObject(raw, context)
	if err != nil {
		return nil, false, err
	}
	return object, true, nil
}

func decodeObject(data []byte, context string) (rawObject, error) {
	var object rawObject
	if err := json.Unmarshal(data, &object); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", context, err)
	}
	if object == nil {
		return nil, fmt.Errorf("failed to parse %s: expected an object", context)
	}
	return object, nil
}

func decodeObjectArray(data []byte, context string) ([]rawObject, error) {
	var objects []rawObject
	if err := json.Unmarshal(data, &objects); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", context, err)
	}
	return objects, nil
}

func mergeKnownObject(original, known rawObject, context string) (rawObject, error) {
	for key, knownValue := range known {
		originalValue, exists := original[key]
		if !exists || isJSONNull(originalValue) || isJSONNull(knownValue) {
			original[key] = knownValue
			continue
		}

		var originalObject rawObject
		var knownObject rawObject
		originalObjectErr := json.Unmarshal(originalValue, &originalObject)
		knownObjectErr := json.Unmarshal(knownValue, &knownObject)
		if originalObjectErr != nil || knownObjectErr != nil || originalObject == nil || knownObject == nil {
			original[key] = knownValue
			continue
		}

		merged, err := mergeKnownObject(originalObject, knownObject, context+"."+key)
		if err != nil {
			return nil, err
		}
		original[key], err = json.Marshal(merged)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal %s.%s: %w", context, key, err)
		}
	}

	return original, nil
}

func isJSONNull(data []byte) bool {
	return bytes.Equal(bytes.TrimSpace(data), []byte("null"))
}

func zeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
