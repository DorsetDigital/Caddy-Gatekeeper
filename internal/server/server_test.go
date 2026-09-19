package server

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

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

func TestChallengeLockedAfterFiveBadCodes(t *testing.T) {
	s := New(Config{AllowedEmail: "developer@example.test", CookieName: "gatekeeper_device", DeviceLifetime: 30 * 24 * time.Hour})
	id := "challenge"
	s.challenges[id] = challenge{Email: "developer@example.test", CodeHash: hashValue("123456"), ReturnURL: "/protected", ExpiresAt: time.Now().Add(time.Minute)}

	for attempt := 1; attempt <= 5; attempt++ {
		form := url.Values{"id": {id}, "code": {"000000"}}
		req := httptest.NewRequest("POST", "/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res := httptest.NewRecorder()
		s.completeChallenge(res, req)
	}

	if _, ok := s.challenges[id]; ok {
		t.Fatal("challenge still exists after five failed attempts")
	}
}

func TestSuccessfulChallengeIsConsumed(t *testing.T) {
	s := New(Config{AllowedEmail: "developer@example.test", CookieName: "gatekeeper_device", DeviceLifetime: 30 * 24 * time.Hour})
	id := "challenge"
	s.challenges[id] = challenge{Email: "developer@example.test", CodeHash: hashValue("123456"), ReturnURL: "/protected", ExpiresAt: time.Now().Add(time.Minute)}

	form := url.Values{"id": {id}, "code": {"123456"}}
	req := httptest.NewRequest("POST", "/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res := httptest.NewRecorder()
	s.completeChallenge(res, req)

	if _, ok := s.challenges[id]; ok {
		t.Fatal("challenge still exists after successful verification")
	}
	if res.Code != 302 {
		t.Fatalf("status = %d, want 302", res.Code)
	}
}
