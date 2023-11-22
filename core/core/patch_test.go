package core

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// sets os.Stdout and os.Stderr to nil
func TestSetsOsStdoutAndStderrToNil(t *testing.T) {
	disableCopaLogger()
	assert.Nil(t, os.Stdout)
	assert.Nil(t, os.Stderr)
}
