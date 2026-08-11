package imagescan

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProcessImages(t *testing.T) {
	emptyResultFunc := func(id ContainerImageIdentifier) string {
		return fmt.Sprintf("empty-%s", id.Repository)
	}

	t.Run("HappyPath", func(t *testing.T) {
		images := []ContainerImageIdentifier{
			{Repository: "repo1", Hash: "hash1"},
			{Repository: "repo2", Hash: "hash2"},
		}

		processFunc := func(id ContainerImageIdentifier) (string, error) {
			return fmt.Sprintf("processed-%s", id.Repository), nil
		}

		results, err := ProcessImages(images, emptyResultFunc, processFunc)
		assert.NoError(t, err)
		assert.Equal(t, []string{"processed-repo1", "processed-repo2"}, results)
	})

	t.Run("PartialFailure", func(t *testing.T) {
		images := []ContainerImageIdentifier{
			{Repository: "repo1", Hash: "hash1"},
			{Repository: "repo2", Hash: "hash2"},
			{Repository: "repo3", Hash: "hash3"},
		}

		processFunc := func(id ContainerImageIdentifier) (string, error) {
			if id.Repository == "repo2" {
				return "", errors.New("api error on repo2")
			}
			return fmt.Sprintf("processed-%s", id.Repository), nil
		}

		results, err := ProcessImages(images, emptyResultFunc, processFunc)

		assert.ErrorContains(t, err, "api error on repo2")
		// The error should be aggregated, and the failed repo should yield the emptyResult.
		assert.Equal(t, []string{"processed-repo1", "empty-repo2", "processed-repo3"}, results)
	})

	t.Run("EmptyHashSkippedInsideProcessFunc", func(t *testing.T) {
		images := []ContainerImageIdentifier{
			{Repository: "repo1", Hash: ""},
			{Repository: "repo2", Hash: "hash2"},
		}

		processFunc := func(id ContainerImageIdentifier) (string, error) {
			if id.Hash == "" {
				return emptyResultFunc(id), nil
			}
			return fmt.Sprintf("processed-%s", id.Repository), nil
		}

		results, err := ProcessImages(images, emptyResultFunc, processFunc)
		assert.NoError(t, err)
		assert.Equal(t, []string{"empty-repo1", "processed-repo2"}, results)
	})
}
