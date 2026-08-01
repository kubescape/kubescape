package decrypt

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/pkg/reportcrypto"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/resourcesresults"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/spf13/cobra"
)

var decryptCmdExamples = `
  # The key is used as raw bytes and must be exactly 32 characters long.
  # Note: openssl rand -base64 32 (44 chars) and openssl rand -hex 32 (64 chars)
  # are NOT valid — they exceed 32 bytes once passed through as raw text.
  export KUBESCAPE_MASTER_KEY="01234567890123456789012345678901"

  # Decrypt an encrypted report
  kubescape decrypt encrypted-report.json

  # Save the decrypted report to a file
  kubescape decrypt encrypted-report.json > decrypted-report.json
`

func GetDecryptCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "decrypt <report.json>",
		Short: "Decrypt report metadata encrypted with kubescape scan --encrypt",
		Long: `Decrypt report metadata using the KUBESCAPE_MASTER_KEY
environment variable.

The decrypted report is written to standard output and can be redirected
to a file.`,
		Example: decryptCmdExamples,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {

			data, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf(
					"failed to read report %q: %w",
					args[0],
					err,
				)
			}

			var report map[string]json.RawMessage

			if err := json.Unmarshal(
				data,
				&report,
			); err != nil {
				return fmt.Errorf(
					"failed to parse report: %w",
					err,
				)
			}

			metadataRaw, ok := report["metadata"]
			if !ok {
				return fmt.Errorf(
					"report metadata not found",
				)
			}

			var metadata reporthandlingv2.Metadata

			if err := json.Unmarshal(
				metadataRaw,
				&metadata,
			); err != nil {
				return fmt.Errorf(
					"failed to parse metadata: %w",
					err,
				)
			}

			dek, err := reportcrypto.DecryptMetadataFromEnv(
				&metadata,
			)
			if err != nil {
				return err
			}

			defer func() {
				for i := range dek {
					dek[i] = 0
				}
			}()

			updatedMetadata, err := json.Marshal(
				metadata,
			)
			if err != nil {
				return fmt.Errorf(
					"failed to marshal metadata: %w",
					err,
				)
			}

			report["metadata"] = updatedMetadata
			resourcesRaw, ok := report["resources"]
			if ok {
				var resources []map[string]json.RawMessage

				if err := json.Unmarshal(
					resourcesRaw,
					&resources,
				); err != nil {
					return fmt.Errorf(
						"failed to parse resources: %w",
						err,
					)
				}

				idMapping := make(map[string]string)

				for i := range resources {

					var oldID string

					if rawID, ok := resources[i]["resourceID"]; ok {
						if err := json.Unmarshal(rawID, &oldID); err != nil {
							return fmt.Errorf(
								"failed to parse resourceID: %w",
								err,
							)
						}
					}

					objectRaw, ok := resources[i]["object"]
					if ok {
						resource, err := workloadinterface.NewWorkload(
							objectRaw,
						)
						if err != nil {
							return fmt.Errorf(
								"failed to parse resource object: %w",
								err,
							)
						}
						if err := reportcrypto.DecryptResourceMetadata(resource, dek); err != nil {
							return err
						}

						if err := reportcrypto.DecryptResourceLabels(resource, dek); err != nil {
							return err
						}

						if err := reportcrypto.DecryptResourceAnnotations(resource, dek); err != nil {
							return err
						}

						if err := reportcrypto.DecryptResourceObjectSourcePath(resource, dek); err != nil {
							return err
						}

						if err := reportcrypto.DecryptContainerMetadata(resource, dek); err != nil {
							return err
						}

						newID := resource.GetID()
						if oldID != "" {
							idMapping[oldID] = newID
						}

						updatedID, err := json.Marshal(newID)
						if err != nil {
							return fmt.Errorf(
								"failed to marshal resourceID: %w",
								err,
							)
						}

						resources[i]["resourceID"] = updatedID

						updatedObject, err := json.Marshal(
							resource.GetWorkload(),
						)
						if err != nil {
							return fmt.Errorf(
								"failed to marshal resource object: %w",
								err,
							)
						}

						resources[i]["object"] = updatedObject
					}

					sourceRaw, ok := resources[i]["source"]
					if !ok {
						continue
					}

					var source reporthandling.Source

					if err := json.Unmarshal(
						sourceRaw,
						&source,
					); err != nil {
						return fmt.Errorf(
							"failed to parse resource source: %w",
							err,
						)
					}

					if err := reportcrypto.DecryptResourceSource(
						&source,
						dek,
					); err != nil {
						return err
					}

					updatedSource, err := json.Marshal(
						source,
					)
					if err != nil {
						return fmt.Errorf(
							"failed to marshal resource source: %w",
							err,
						)
					}

					resources[i]["source"] = updatedSource
				}

				updatedResources, err := json.Marshal(
					resources,
				)
				if err != nil {
					return fmt.Errorf(
						"failed to marshal resources: %w",
						err,
					)
				}

				report["resources"] = updatedResources
				resultsRaw, ok := report["results"]
				if ok {
					var results []resourcesresults.Result
					if err := json.Unmarshal(
						resultsRaw,
						&results,
					); err != nil {
						return fmt.Errorf(
							"failed to parse results: %w",
							err,
						)
					}

					remapResults(results, idMapping)
					updatedResults, err := json.Marshal(
						results,
					)
					if err != nil {
						return fmt.Errorf(
							"failed to marshal results: %w",
							err,
						)
					}

					report["results"] = updatedResults
				}
			}
			encoder := json.NewEncoder(os.Stdout)
			encoder.SetIndent("", "  ")

			return encoder.Encode(report)
		},
	}
}

// remapResults restores all resource ID references that were rewritten
// during encryption so they remain consistent with the decrypted resources.
func remapResults(results []resourcesresults.Result, idMapping map[string]string) {
	for i := range results {
		results[i].ResourceID = remapResourceID(
			results[i].ResourceID,
			idMapping,
		)

		if results[i].PrioritizedResource != nil {
			results[i].PrioritizedResource.ResourceID =
				remapResourceID(
					results[i].PrioritizedResource.ResourceID,
					idMapping,
				)
		}

		for controlIndex := range results[i].AssociatedControls {
			for ruleIndex := range results[i].AssociatedControls[controlIndex].ResourceAssociatedRules {

				rule := &results[i].AssociatedControls[controlIndex].ResourceAssociatedRules[ruleIndex]

				for pathIndex := range rule.Paths {
					rule.Paths[pathIndex].ResourceID =
						remapResourceID(
							rule.Paths[pathIndex].ResourceID,
							idMapping,
						)
				}

				for relatedIndex := range rule.RelatedResourcesIDs {
					rule.RelatedResourcesIDs[relatedIndex] =
						remapResourceID(
							rule.RelatedResourcesIDs[relatedIndex],
							idMapping,
						)
				}
			}
		}
	}
}

// remapResourceID restores a resource ID if it was rewritten during
// encryption. Unknown IDs are returned unchanged.
func remapResourceID(
	id string,
	idMapping map[string]string,
) string {

	if mappedID, ok := idMapping[id]; ok {
		return mappedID
	}

	return id
}
