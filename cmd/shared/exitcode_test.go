package shared

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestExitCode pins that only an ExitError changes the exit code, and that it does not change the message.
func TestExitCode(t *testing.T) {
	cause := errors.New("2 of 3 context(s) failed")
	exitErr := &ExitError{Code: 2, Err: cause}

	assert.Equal(t, 0, ExitCode(nil))
	assert.Equal(t, 1, ExitCode(cause))
	assert.Equal(t, 2, ExitCode(exitErr))
	assert.Equal(t, 2, ExitCode(fmt.Errorf("scan: %w", exitErr)), "the code survives wrapping")
	assert.Equal(t, cause.Error(), exitErr.Error())
	assert.ErrorIs(t, exitErr, cause)
}
