package server

import "testing"

func TestSafeReturnURL(t *testing.T) {
	tests := map[string]string{
		"": "/",
		"/admin": "/admin",
		"/admin?foo=bar": "/admin?foo=bar",
		"https://evil.test/x": "/",
		"//evil.test/x": "/",
	}
	for input, expected := range tests {
		if actual := safeReturnURL(input); actual != expected {
			t.Fatalf("safeReturnURL(%q) = %q, want %q", input, actual, expected)
		}
	}
}
