package identity

import "testing"

func TestHasherNormalisesIdentity(t *testing.T) {
	h := NewHasher("test-secret")
	a := h.ID(" Developer@Example.Test ")
	b := h.ID("developer@example.test")
	if a != b { t.Fatal("normalised identities should have the same ID") }
	if a == "developer@example.test" { t.Fatal("identity ID must not contain plaintext identity") }
}

func TestHasherIsKeyed(t *testing.T) {
	if NewHasher("one").ID("developer@example.test") == NewHasher("two").ID("developer@example.test") {
		t.Fatal("different keys must produce different identity IDs")
	}
}
