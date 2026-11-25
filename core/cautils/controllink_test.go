package cautils

import (
	"testing"
)

// Returns a valid URL when given a valid control ID.
func TestGetControlLink_ValidControlID(t *testing.T) {
	controlID := "cis-1.1.3"
	expectedURL := "https://hub.armosec.io/docs/cis-1-1-3"

	result := GetControlLink(controlID)

	if result != expectedURL {
		t.Errorf("Expected URL: %s, but got: %s", expectedURL, result)
	}
}

// Replaces dots with hyphens in the control ID to generate the correct documentation link.
func TestGetControlLink_DotsInControlID(t *testing.T) {
	controlID := "cis.1.1.3"
	expectedURL := "https://hub.armosec.io/docs/cis-1-1-3"

	result := GetControlLink(controlID)

	if result != expectedURL {
		t.Errorf("Expected URL: %s, but got: %s", expectedURL, result)
	}
}

// Returns a lowercase URL.
func TestGetControlLink_LowercaseURL(t *testing.T) {
	controlID := "CIS-1.1.3"
	expectedURL := "https://hub.armosec.io/docs/cis-1-1-3"

	result := GetControlLink(controlID)

	if result != expectedURL {
		t.Errorf("Expected URL: %s, but got: %s", expectedURL, result)
	}
}

// Returns URL to armosec docs when given an empty control ID.
func TestGetControlLink_EmptyControlID(t *testing.T) {
	controlID := ""
	expectedURL := "https://hub.armosec.io/docs/"

	result := GetControlLink(controlID)

	if result != expectedURL {
		t.Errorf("Expected URL: %s, but got: %s", expectedURL, result)
	}
}

// Trims surrounding whitespace from control IDs and falls back to base URL for whitespace-only IDs.
func TestGetControlLink_WhitespaceHandling(t *testing.T) {
	tests := []struct {
		name        string
		controlID   string
		expectedURL string
	}{
		{
			name:        "padded CIS control",
			controlID:   "  cis-1.1.3  ",
			expectedURL: "https://hub.armosec.io/docs/cis-1-1-3",
		},
		{
			name:        "padded Armo control",
			controlID:   "\tC-0001 \n",
			expectedURL: "https://hub.armosec.io/docs/c-0001",
		},
		{
			name:        "whitespace only",
			controlID:   "   ",
			expectedURL: "https://hub.armosec.io/docs/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetControlLink(tt.controlID)
			if result != tt.expectedURL {
				t.Errorf("GetControlLink(%q) = %q; want %q", tt.controlID, result, tt.expectedURL)
			}
		})
	}
}
