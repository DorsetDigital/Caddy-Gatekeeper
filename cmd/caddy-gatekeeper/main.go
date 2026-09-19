package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/server"
)

func main() {
	addr := env("GATEKEEPER_LISTEN", ":9080")
	app := server.New(server.Config{
		AllowedEmail: env("GATEKEEPER_ALLOWED_EMAIL", "developer@example.test"),
		CookieName: "gatekeeper_device",
		CookieSecure: env("GATEKEEPER_COOKIE_SECURE", "false") == "true",
		DeviceLifetime: 30 * 24 * time.Hour,
	})
	log.Printf("caddy-gatekeeper listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, app.Handler()))
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" { return value }
	return fallback
}
