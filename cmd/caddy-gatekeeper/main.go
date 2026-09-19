package main

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/identity"
	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/server"
)

func main() {
	addr := env("GATEKEEPER_LISTEN", ":9080")
	app := server.New(server.Config{
		AllowedEmail: env("GATEKEEPER_ALLOWED_EMAIL", "developer@example.test"),
		CookieName: "gatekeeper_device",
		CookieSecure: env("GATEKEEPER_COOKIE_SECURE", "false") == "true",
		DeviceLifetime: 30 * 24 * time.Hour,
		MaxAttempts: envInt("GATEKEEPER_MAX_ATTEMPTS", 3),
		IdentityHasher: identity.NewHasher(requiredEnv("GATEKEEPER_IDENTITY_KEY")),
	})
	log.Printf("caddy-gatekeeper listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, app.Handler()))
}

func requiredEnv(name string) string {
	value := os.Getenv(name)
	if value == "" { log.Fatalf("%s is required", name) }
	return value
}

func envInt(name string, fallback int) int {
	value := os.Getenv(name)
	if value == "" { return fallback }
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		log.Fatalf("%s must be a positive integer", name)
	}
	return parsed
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" { return value }
	return fallback
}
