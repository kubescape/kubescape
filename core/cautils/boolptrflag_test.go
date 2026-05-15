package cautils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBoolPtrFlag_Defaults(t *testing.T) {
	flag := NewBoolPtr(nil)

	assert.Equal(t, "bool", flag.Type())
	assert.Equal(t, "", flag.String())
	assert.Nil(t, flag.Get())
	assert.False(t, flag.GetBool())
}

func TestBoolPtrFlag_NewValue(t *testing.T) {
	value := true
	flag := NewBoolPtr(&value)

	assert.Equal(t, "true", flag.String())
	assert.NotNil(t, flag.Get())
	assert.True(t, flag.GetBool())
}

func TestBoolPtrFlag_SetBool(t *testing.T) {
	flag := NewBoolPtr(nil)

	flag.SetBool(true)
	assert.Equal(t, "true", flag.String())
	assert.True(t, flag.GetBool())

	flag.SetBool(false)
	assert.Equal(t, "false", flag.String())
	assert.False(t, flag.GetBool())
}

func TestBoolPtrFlag_Set(t *testing.T) {
	flag := NewBoolPtr(nil)

	assert.NoError(t, flag.Set("true"))
	assert.True(t, flag.GetBool())

	assert.NoError(t, flag.Set("false"))
	assert.False(t, flag.GetBool())

	assert.NoError(t, flag.Set("unknown"))
	assert.False(t, flag.GetBool())
}
