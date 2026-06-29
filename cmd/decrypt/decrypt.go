package decrypt

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v3/core/pkg/reportcrypto"
	"github.com/kubescape/opa-utils/reporthandling"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
	"github.com/spf13/cobra"
)

func GetDecryptCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "decrypt <report.json>",
		Short: "Decrypt encrypted Kubescape reports",
		Args:  cobra.ExactArgs(1),
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

						if err := reportcrypto.DecryptResourceMetadata(
							resource,
							dek,
						); err != nil {
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
					var results []map[string]json.RawMessage

					if err := json.Unmarshal(
						resultsRaw,
						&results,
					); err != nil {
						return fmt.Errorf(
							"failed to parse results: %w",
							err,
						)
					}

					for i := range results {
						var resourceID string

						resourceIDRaw, ok := results[i]["resourceID"]
						if !ok {
							continue
						}

						if err := json.Unmarshal(
							resourceIDRaw,
							&resourceID,
						); err != nil {
							return fmt.Errorf(
								"failed to parse result resourceID: %w",
								err,
							)
						}

						newID := resourceID
						if mappedID, ok := idMapping[resourceID]; ok {
							newID = mappedID
						}
						updatedID, err := json.Marshal(newID)
						if err != nil {
							return fmt.Errorf(
								"failed to marshal result resourceID: %w",
								err,
							)
						}

						results[i]["resourceID"] = updatedID
					}

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
