package cautils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBoolPtrFlag(t *testing.T) {
	t.Run("NewBoolPtr", func(t *testing.T) {
		b := true
		bpf := NewBoolPtr(&b)
		assert.Equal(t, &b, bpf.valPtr)
	})

	t.Run("Type", func(t *testing.T) {
		bpf := BoolPtrFlag{}
		assert.Equal(t, "bool", bpf.Type())
	})

	t.Run("String", func(t *testing.T) {
		b := true
		bpf := NewBoolPtr(&b)
		assert.Equal(t, "true", bpf.String())

		bpfNil := BoolPtrFlag{}
		assert.Equal(t, "", bpfNil.String())
	})

	t.Run("Get", func(t *testing.T) {
		b := true
		bpf := NewBoolPtr(&b)
		assert.Equal(t, &b, bpf.Get())
	})

	t.Run("GetBool", func(t *testing.T) {
		b := true
		bpf := NewBoolPtr(&b)
		assert.True(t, bpf.GetBool())

		bpfNil := BoolPtrFlag{}
		assert.False(t, bpfNil.GetBool())
	})

	t.Run("SetBool", func(t *testing.T) {
		bpf := BoolPtrFlag{}
		bpf.SetBool(true)
		assert.True(t, bpf.GetBool())
	})

	t.Run("Set", func(t *testing.T) {
		bpf := BoolPtrFlag{}
		err := bpf.Set("true")
		assert.NoError(t, err)
		assert.True(t, bpf.GetBool())

		err = bpf.Set("false")
		assert.NoError(t, err)
		assert.False(t, bpf.GetBool())
		
		err = bpf.Set("other")
		assert.NoError(t, err)
		assert.False(t, bpf.GetBool())
	})
}

func TestUnique(t *testing.T) {
	tests := []struct {
		name  string
		items []string
		want  []string
	}{
		{
			name:  "empty",
			items: []string{},
			want:  []string{},
		},
		{
			name:  "no duplicates",
			items: []string{"a", "b", "c"},
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "with duplicates",
			items: []string{"a", "b", "a", "c", "b"},
			want:  []string{"a", "b", "c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := unique(tt.items)
			assert.Equal(t, tt.want, got)
		})
	}
}



func TestIsHTTPURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "http",
			input: "http://example.com",
			want:  true,
		},
		{
			name:  "https",
			input: "https://example.com",
			want:  true,
		},
		{
			name:  "ftp",
			input: "ftp://example.com",
			want:  false,
		},
		{
			name:  "file path",
			input: "/path/to/file",
			want:  false,
		},
		{
			name:  "empty",
			input: "",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isHTTPURL(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFormats(t *testing.T) {
	tests := []struct {
		name     string
		scanInfo *ScanInfo
		want     []string
	}{
		{
			name: "empty",
			scanInfo: &ScanInfo{
				Format: "",
			},
			want: []string{},
		},
		{
			name: "single format",
			scanInfo: &ScanInfo{
				Format: "json",
			},
			want: []string{"json"},
		},
		{
			name: "multiple formats",
			scanInfo: &ScanInfo{
				Format: "json,pdf",
			},
			want: []string{"json", "pdf"},
		},
		{
			name: "with spaces",
			scanInfo: &ScanInfo{
				Format: "json, pdf ,  html ",
			},
			want: []string{"json", "pdf", "html"},
		},
		{
			name: "with duplicates",
			scanInfo: &ScanInfo{
				Format: "json, pdf, json",
			},
			want: []string{"json", "pdf"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.scanInfo.Formats()
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}

func TestContains(t *testing.T) {
	scanInfo := &ScanInfo{
		PolicyIdentifier: []PolicyIdentifier{
			{Identifier: "c-0012", Kind: "Control"},
			{Identifier: "nsa", Kind: "Framework"},
		},
	}

	assert.True(t, scanInfo.contains("c-0012"))
	assert.True(t, scanInfo.contains("nsa"))
	assert.False(t, scanInfo.contains("non-existent"))
}
