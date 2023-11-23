package hostsensorutils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Initializes a workerPool struct with default values and returns it
func TestNewWorkerPoolDefaultValues(t *testing.T) {
	wp := newWorkerPool()
	assert.Equal(t, noOfWorkers, wp.noOfWorkers)
	assert.NotNil(t, wp.jobs)
	assert.NotNil(t, wp.results)
	assert.NotNil(t, wp.done)
}
