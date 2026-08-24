package imagescan

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type failingRegistryReader struct {
	data []byte
	err  error
}

func (r *failingRegistryReader) Read(p []byte) (int, error) {
	if len(r.data) > 0 {
		n := copy(p, r.data)
		r.data = r.data[n:]
		return n, nil
	}
	return 0, r.err
}

func TestReadRegistryAPIResponse(t *testing.T) {
	tests := []struct {
		name      string
		reader    io.Reader
		limit     int64
		want      string
		wantError string
	}{
		{name: "body below limit", reader: strings.NewReader("payload"), limit: 8, want: "payload"},
		{name: "body exactly at limit", reader: strings.NewReader("12345678"), limit: 8, want: "12345678"},
		{
			name:      "body exceeds limit by one byte",
			reader:    strings.NewReader("123456789"),
			limit:     8,
			wantError: "exceeds the 8-byte limit",
		},
		{
			name: "reader failure",
			reader: &failingRegistryReader{
				data: []byte("partial"),
				err:  errors.New("connection reset"),
			},
			limit:     64,
			wantError: "connection reset",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readRegistryAPIResponse(tt.reader, tt.limit)
			if tt.wantError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
				assert.Nil(t, got)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestProcessImages(t *testing.T) {
	t.Run("HappyPath", func(t *testing.T) {
		images := []ContainerImageIdentifier{
			{Repository: "repo1", Hash: "hash1"},
			{Repository: "repo2", Hash: "hash2"},
		}

		processFunc := func(id ContainerImageIdentifier) (string, error) {
			return fmt.Sprintf("processed-%s", id.Repository), nil
		}

		results, err := ProcessImages(images, processFunc)
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
				return fmt.Sprintf("partial-%s", id.Repository), errors.New("api error on repo2")
			}
			return fmt.Sprintf("processed-%s", id.Repository), nil
		}

		results, err := ProcessImages(images, processFunc)

		assert.ErrorContains(t, err, "api error on repo2")
		// The error should be aggregated, and the failed repo should yield the partial result.
		assert.Equal(t, []string{"processed-repo1", "partial-repo2", "processed-repo3"}, results)
	})

	t.Run("EmptyHashSkippedInsideProcessFunc", func(t *testing.T) {
		images := []ContainerImageIdentifier{
			{Repository: "repo1", Hash: ""},
			{Repository: "repo2", Hash: "hash2"},
		}

		processFunc := func(id ContainerImageIdentifier) (string, error) {
			if id.Hash == "" {
				return fmt.Sprintf("empty-%s", id.Repository), nil
			}
			return fmt.Sprintf("processed-%s", id.Repository), nil
		}

		results, err := ProcessImages(images, processFunc)
		assert.NoError(t, err)
		assert.Equal(t, []string{"empty-repo1", "processed-repo2"}, results)
	})
}
