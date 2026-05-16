package listener

import "testing"

func TestGetPort(t *testing.T) {
	t.Run("returns env var when set", func(t *testing.T) {
		t.Setenv("KS_PORT", "9090")
		if got := getPort(); got != "9090" {
			t.Fatalf("getPort() = %q, want %q", got, "9090")
		}
	})

	t.Run("returns default when unset", func(t *testing.T) {
		t.Setenv("KS_PORT", "")
		if got := getPort(); got != "8080" {
			t.Fatalf("getPort() = %q, want %q", got, "8080")
		}
	})
}

func TestGetOffline(t *testing.T) {
	t.Run("returns true only for literal true", func(t *testing.T) {
		t.Setenv("KS_OFFLINE", "true")
		if !getOffline() {
			t.Fatal("getOffline() = false, want true")
		}
	})

	t.Run("returns false when unset", func(t *testing.T) {
		t.Setenv("KS_OFFLINE", "")
		if getOffline() {
			t.Fatal("getOffline() = true, want false")
		}
	})

	t.Run("returns false for other values", func(t *testing.T) {
		t.Setenv("KS_OFFLINE", "TRUE")
		if getOffline() {
			t.Fatal("getOffline() = true, want false")
		}
	})
}
