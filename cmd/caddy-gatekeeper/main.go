package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/identity"
	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/server"
	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/store"
)

func main() {
	addr := env("GATEKEEPER_LISTEN", ":9080")
	state, err := buildStore(context.Background())
	if err != nil { log.Fatalf("initialise state store: %v", err) }
	defer state.Close()

	app := server.New(server.Config{
		AllowedEmail: env("GATEKEEPER_ALLOWED_EMAIL", "developer@example.test"),
		CookieName: "gatekeeper_device",
		CookieSecure: env("GATEKEEPER_COOKIE_SECURE", "false") == "true",
		DeviceLifetime: 30 * 24 * time.Hour,
		MaxAttempts: envInt("GATEKEEPER_MAX_ATTEMPTS", 3),
		IdentityHasher: identity.NewHasher(requiredEnv("GATEKEEPER_IDENTITY_KEY")),
		Store: state,
	})
	log.Printf("caddy-gatekeeper listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, app.Handler()))
}

func buildStore(ctx context.Context)(store.Store,error){
	if env("GATEKEEPER_STORE","memory")!="valkey"{return store.NewMemory(),nil}
	addrs:=strings.Split(requiredEnv("GATEKEEPER_VALKEY_ADDRS"),",")
	for i:=range addrs{addrs[i]=strings.TrimSpace(addrs[i])}
	return store.NewValkey(ctx,store.ValkeyConfig{
		Mode:env("GATEKEEPER_VALKEY_MODE","standalone"),
		Addrs:addrs,
		Username:os.Getenv("GATEKEEPER_VALKEY_USERNAME"),
		Password:os.Getenv("GATEKEEPER_VALKEY_PASSWORD"),
		TLS:env("GATEKEEPER_VALKEY_TLS","false")=="true",
		Prefix:env("GATEKEEPER_VALKEY_PREFIX","gatekeeper:"),
	})
}
func requiredEnv(name string) string { value:=os.Getenv(name);if value==""{log.Fatalf("%s is required",name)};return value }
func envInt(name string,fallback int)int{value:=os.Getenv(name);if value==""{return fallback};parsed,err:=strconv.Atoi(value);if err!=nil||parsed<1{log.Fatalf("%s must be a positive integer",name)};return parsed}
func env(name,fallback string)string{if value:=os.Getenv(name);value!=""{return value};return fallback}
