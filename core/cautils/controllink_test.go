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
