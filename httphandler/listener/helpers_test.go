package listener

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRecoverFunc_NoPanic(t *testing.T) {
	// When no panic occurs, RecoverFunc should be a no-op.
	recorder := httptest.NewRecorder()
	func() {
		defer RecoverFunc(recorder)
		// no panic here
	}()

	// Response should not have been written to
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Empty(t, recorder.Body.String())
}

func TestRecoverFunc_WithStringPanic(t *testing.T) {
	recorder := httptest.NewRecorder()
	func() {
		defer RecoverFunc(recorder)
		panic("something went wrong")
	}()

	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
	assert.NotEmpty(t, recorder.Body.String())
}

func TestRecoverFunc_WithErrorPanic(t *testing.T) {
	recorder := httptest.NewRecorder()
	func() {
		defer RecoverFunc(recorder)
		panic(assert.AnError)
	}()

	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
}

func TestRecoverFunc_WithIntPanic(t *testing.T) {
	recorder := httptest.NewRecorder()
	func() {
		defer RecoverFunc(recorder)
		panic(42)
	}()

	assert.Equal(t, http.StatusInternalServerError, recorder.Code)
}
