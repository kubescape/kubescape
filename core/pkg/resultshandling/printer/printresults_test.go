package printer

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetWriter_EmptyFileName(t *testing.T) {
	ctx := context.Background()
	outputFile := ""
	file := GetWriter(ctx, outputFile)
	assert.Equal(t, os.Stdout, file)
}

func TestGetWriter_NonEmptyFileName(t *testing.T) {
	ctx := context.Background()
	outputFile := "temp.txt"
	file := GetWriter(ctx, outputFile)
	assert.NotEqual(t, os.Stdout, file)
	err := os.Remove(outputFile)
	assert.Nil(t, err)
}
