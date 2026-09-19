package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

type Hasher struct { key []byte }

func NewHasher(key string) Hasher { return Hasher{key: []byte(key)} }

func (h Hasher) ID(value string) string {
	normalised := strings.ToLower(strings.TrimSpace(value))
	mac := hmac.New(sha256.New, h.key)
	_, _ = mac.Write([]byte(normalised))
	return hex.EncodeToString(mac.Sum(nil))
}
