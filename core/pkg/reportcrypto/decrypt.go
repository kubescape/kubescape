package reportcrypto

import (
	"fmt"
	"strings"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/opa-utils/reporthandling"
	reporthandlingv2 "github.com/kubescape/opa-utils/reporthandling/v2"
)

// DEKFromMetadata extracts and unwraps the DEK stored in
// EncryptionMetadata using the supplied master key.
//
// This is the first step of the decryption workflow:
//
//	EncryptionMetadata.EncryptedDEK
//	          ↓
//	     UnwrapDEK()
//	          ↓
//	          DEK

func DEKFromMetadata(metadata *reporthandlingv2.Metadata, masterKey []byte) ([]byte, error) {

	if metadata == nil {
		return nil, fmt.Errorf("metadata is nil")
	}

	if metadata.EncryptionMetadata == nil {
		return nil, fmt.Errorf("encryption metadata not found")
	}

	if metadata.EncryptionMetadata.EncryptedDEK == "" {
		return nil, fmt.Errorf("encrypted DEK not found")
	}

	return UnwrapDEK(
		metadata.EncryptionMetadata.EncryptedDEK,
		masterKey,
	)
}

// DecryptRepoContextMetadata decrypts all repository context fields
// previously encrypted by ApplyEncrypted.
//
// This operation mutates the supplied metadata object in place.
//
// Current fields:
//
//   - Repo
//   - Owner
//   - Branch
//   - RemoteURL
//   - LastCommit.Message
//   - DefaultBranch
//   - LocalRootPath
//   - LastCommit.Hash
//   - LastCommit.CommitterName
//   - LastCommit.CommitterEmail
//
// Additional fields can be added as encryption coverage expands.

func DecryptRepoContextMetadata(metadata *reporthandlingv2.Metadata, masterKey []byte) error {

	dek, err := DEKFromMetadata(
		metadata,
		masterKey,
	)
	if err != nil {
		return err
	}

	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()

	repoMetadata :=
		metadata.ContextMetadata.RepoContextMetadata

	if repoMetadata == nil {
		return nil
	}

	if repoMetadata.Repo != "" {
		repoMetadata.Repo, err =
			decryptIfEncrypted(repoMetadata.Repo, dek)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt repo: %w",
				err,
			)
		}
	}

	if repoMetadata.Owner != "" {
		repoMetadata.Owner, err =
			decryptIfEncrypted(repoMetadata.Owner, dek)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt owner: %w",
				err,
			)
		}
	}

	if repoMetadata.Branch != "" {
		repoMetadata.Branch, err =
			decryptIfEncrypted(repoMetadata.Branch, dek)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt branch: %w",
				err,
			)
		}
	}

	if repoMetadata.DefaultBranch != "" {
		repoMetadata.DefaultBranch, err =
			decryptIfEncrypted(
				repoMetadata.DefaultBranch,
				dek,
			)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt default branch: %w",
				err,
			)
		}
	}

	if repoMetadata.RemoteURL != "" {
		repoMetadata.RemoteURL, err =
			decryptIfEncrypted(
				repoMetadata.RemoteURL,
				dek,
			)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt remoteURL: %w",
				err,
			)
		}
	}

	if repoMetadata.LocalRootPath != "" {
		repoMetadata.LocalRootPath, err =
			decryptIfEncrypted(
				repoMetadata.LocalRootPath,
				dek,
			)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt localRootPath: %w",
				err,
			)
		}
	}

	if err := decryptLastCommit(
		&repoMetadata.LastCommit,
		dek,
	); err != nil {
		return err
	}

	return nil
}

// decryptLastCommit decrypts all commit metadata fields that may have
// been encrypted by transformLastCommit.
//
// This operation mutates the supplied LastCommit object in place.

func decryptLastCommit(commit *reporthandling.LastCommit, dek []byte) error {
	if commit == nil {
		return nil
	}

	var err error

	if commit.Hash != "" {
		commit.Hash, err = decryptIfEncrypted(
			commit.Hash,
			dek,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt commit hash: %w",
				err,
			)
		}
	}

	if commit.CommitterName != "" {
		commit.CommitterName, err = decryptIfEncrypted(
			commit.CommitterName,
			dek,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt committer name: %w",
				err,
			)
		}
	}

	if commit.CommitterEmail != "" {
		commit.CommitterEmail, err = decryptIfEncrypted(
			commit.CommitterEmail,
			dek,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt committer email: %w",
				err,
			)
		}
	}

	if commit.Message != "" {
		commit.Message, err = decryptIfEncrypted(
			commit.Message,
			dek,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt commit message: %w",
				err,
			)
		}
	}

	return nil
}

// DecryptResourceSource decrypts source metadata previously encrypted
// by transformResourceSource.
//
// This operation mutates the supplied Source object in place.
//
// Current coverage:
//
//   - Path
//   - RelativePath
//   - HelmPath
//   - HelmChartName
//   - HelmTemplateFile
//   - HelmValuesPaths
//   - KustomizeDirectoryName
//   - LastCommit.Hash
//   - LastCommit.CommitterName
//   - LastCommit.CommitterEmail
//   - LastCommit.Message

func DecryptResourceSource(source *reporthandling.Source, dek []byte) error {
	if source == nil {
		return nil
	}

	var err error

	if source.Path != "" {
		source.Path, err = decryptIfEncrypted(
			source.Path,
			dek,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt path: %w",
				err,
			)
		}
	}

	if source.RelativePath != "" {
		source.RelativePath, err = decryptIfEncrypted(
			source.RelativePath,
			dek,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt relative path: %w",
				err,
			)
		}
	}

	if source.HelmPath != "" {
		source.HelmPath, err = decryptIfEncrypted(
			source.HelmPath,
			dek,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt helm path: %w",
				err,
			)
		}
	}

	if source.HelmChartName != "" {
		source.HelmChartName, err = decryptIfEncrypted(
			source.HelmChartName,
			dek,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt helm chart name: %w",
				err,
			)
		}
	}

	if source.HelmTemplateFile != "" {
		source.HelmTemplateFile, err = decryptIfEncrypted(
			source.HelmTemplateFile,
			dek,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt helm template file: %w",
				err,
			)
		}
	}

	if source.KustomizeDirectoryName != "" {
		source.KustomizeDirectoryName, err = decryptIfEncrypted(
			source.KustomizeDirectoryName,
			dek,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt kustomize directory name: %w",
				err,
			)
		}
	}

	for i := range source.HelmValuesPaths {
		if source.HelmValuesPaths[i] == "" {
			continue
		}

		source.HelmValuesPaths[i], err = decryptIfEncrypted(
			source.HelmValuesPaths[i],
			dek,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt helm values path[%d]: %w",
				i,
				err,
			)
		}
	}

	if err := decryptLastCommit(
		&source.LastCommit,
		dek,
	); err != nil {
		return err
	}

	return nil
}

// DecryptResourceMetadata decrypts resource identifiers previously
// encrypted by transformResourceMetadata.
//
// This operation mutates the supplied resource metadata in place.
//
// Current coverage:
//
//   - Name
//   - Namespace

func DecryptResourceMetadata(resource workloadinterface.IMetadata, dek []byte) error {
	if resource == nil {
		return nil
	}

	var err error

	if name := resource.GetName(); name != "" {
		name, err = decryptIfEncrypted(
			name,
			dek,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt resource name: %w",
				err,
			)
		}

		resource.SetName(name)
	}

	if namespace := resource.GetNamespace(); namespace != "" {
		namespace, err = decryptIfEncrypted(
			namespace,
			dek,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt resource namespace: %w",
				err,
			)
		}

		resource.SetNamespace(namespace)
	}

	return nil
}

func decryptIfEncrypted(value string, dek []byte) (string, error) {
	if value == "" {
		return value, nil
	}

	value = strings.TrimSpace(value)

	if !strings.HasPrefix(value, "ENC[") {
		return value, nil
	}

	return DecryptString(value, dek)
}

// DecryptResourceLabels restores encrypted resource label values.
//
// Every label value is passed through decryptIfEncrypted, which leaves
// plaintext values unchanged while restoring encrypted values.

func DecryptResourceLabels(resource workloadinterface.IMetadata, dek []byte) error {

	if resource == nil {
		return nil
	}

	bw, ok := resource.(workloadinterface.IWorkload)
	if !ok {
		return nil
	}

	labels := bw.GetLabels()
	if len(labels) == 0 {
		return nil
	}

	for key, value := range labels {
		if value == "" {
			continue
		}

		decryptedValue, err := decryptIfEncrypted(
			value,
			dek,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt label %q: %w",
				key,
				err,
			)
		}

		bw.SetLabel(
			key,
			decryptedValue,
		)
	}

	return nil
}

// DecryptResourceAnnotations restores encrypted annotation values
// throughout a workload object, including nested workload templates.

func DecryptResourceAnnotations(resource workloadinterface.IMetadata, dek []byte) error {

	if resource == nil {
		return nil
	}

	obj := resource.GetObject()
	if obj == nil {
		return nil
	}

	if err := decryptAnnotationNodes(
		obj,
		dek,
	); err != nil {
		return err
	}

	resource.SetObject(obj)

	return nil
}

// decryptAnnotationNodes recursively traverses resource objects to
// locate metadata.annotations blocks regardless of workload nesting
// depth.

func decryptAnnotationNodes(node any, dek []byte) error {

	switch v := node.(type) {

	case map[string]any:

		if err := decryptAnnotationMap(
			v,
			dek,
		); err != nil {
			return err
		}

		for _, child := range v {
			if err := decryptAnnotationNodes(
				child,
				dek,
			); err != nil {
				return err
			}
		}

	case []any:

		for _, item := range v {
			if err := decryptAnnotationNodes(
				item,
				dek,
			); err != nil {
				return err
			}
		}
	}

	return nil
}

// decryptAnnotationMap restores encrypted annotation values while
// preserving annotation keys.

func decryptAnnotationMap(obj map[string]any, dek []byte) error {

	rawMetadata, ok := obj["metadata"]
	if !ok || rawMetadata == nil {
		return nil
	}

	metadata, ok := rawMetadata.(map[string]any)
	if !ok {
		return nil
	}

	rawAnnotations, ok := metadata["annotations"]
	if !ok || rawAnnotations == nil {
		return nil
	}

	annotations, ok := rawAnnotations.(map[string]any)
	if !ok {
		return nil
	}

	for key, value := range annotations {

		str, ok := value.(string)
		if !ok || str == "" {
			continue
		}

		decryptedValue, err := decryptIfEncrypted(
			str,
			dek,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to decrypt annotation %q: %w",
				key,
				err,
			)
		}

		annotations[key] = decryptedValue
	}

	return nil
}

// DecryptResourceObjectSourcePath restores object.sourcePath while
// preserving trailing line-number context.

func DecryptResourceObjectSourcePath(resource workloadinterface.IMetadata, dek []byte) error {

	if resource == nil {
		return nil
	}

	obj := resource.GetObject()
	if obj == nil {
		return nil
	}

	rawSourcePath, ok := obj["sourcePath"]
	if !ok {
		return nil
	}

	sourcePath, ok := rawSourcePath.(string)
	if !ok || sourcePath == "" {
		return nil
	}

	decryptedPath, err := decryptSourcePath(
		sourcePath,
		dek,
	)
	if err != nil {
		return err
	}

	obj["sourcePath"] = decryptedPath
	resource.SetObject(obj)

	return nil
}

// decryptSourcePath restores the path portion of a sourcePath while
// preserving any trailing line-number suffix.

func decryptSourcePath(sourcePath string, dek []byte) (string, error) {

	lastColon := strings.LastIndex(
		sourcePath,
		":",
	)

	if lastColon == -1 {
		return decryptIfEncrypted(
			sourcePath,
			dek,
		)
	}

	pathPart := sourcePath[:lastColon]
	linePart := sourcePath[lastColon:]

	if pathPart == "" {
		return decryptIfEncrypted(
			sourcePath,
			dek,
		)
	}

	decryptedPath, err := decryptIfEncrypted(
		pathPart,
		dek,
	)
	if err != nil {
		return "",
			fmt.Errorf(
				"failed to decrypt source path: %w",
				err,
			)
	}

	return decryptedPath + linePart, nil
}
