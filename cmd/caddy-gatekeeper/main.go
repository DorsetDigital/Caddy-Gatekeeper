package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/access"
	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/identity"
	maildelivery "github.com/DorsetDigital/Caddy-Gatekeeper/internal/mail"
	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/server"
	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/management"
	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/site"
	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/store"
)

func main() {
	addr := env("GATEKEEPER_LISTEN", ":9080")
	state, err := buildStore(context.Background())
	if err != nil { log.Fatalf("initialise state store: %v", err) }
	defer state.Close()
	var sites site.Repository
	if valkeyStore,ok:=state.(*store.Valkey);ok{sites=site.NewValkey(valkeyStore.Client(),valkeyStore.Prefix())}else{sites=site.NewMemory()}
	apiAddr:=env("GATEKEEPER_API_LISTEN",":9081")
	api:=management.New(sites,requiredEnv("GATEKEEPER_API_TOKEN"))
	go func(){
		log.Printf("caddy-gatekeeper management API listening on %s",apiAddr)
		apiServer:=&http.Server{Addr:apiAddr,Handler:api.Handler(),ReadHeaderTimeout:5*time.Second,ReadTimeout:10*time.Second,WriteTimeout:15*time.Second,IdleTimeout:60*time.Second}
		if err:=apiServer.ListenAndServe();err!=nil&&err!=http.ErrServerClosed{log.Fatalf("management API: %v",err)}
	}()

	app := server.New(server.Config{
		AccessMatcher: access.NewMatcher(developmentAccessRules()),
		Sites: sites,
		CookieName: "gatekeeper_device",
		CookieSecure: env("GATEKEEPER_COOKIE_SECURE", "false") == "true",
		DeviceLifetime: 30 * 24 * time.Hour,
		MaxAttempts: envInt("GATEKEEPER_MAX_ATTEMPTS", 3),
		IdentityHasher: identity.NewHasher(requiredEnv("GATEKEEPER_IDENTITY_KEY")),
		Store: state,
		MailSender: buildMailSender(),
	})
	log.Printf("caddy-gatekeeper listening on %s", addr)
	httpServer:=&http.Server{
		Addr:addr,
		Handler:app.Handler(),
		ReadHeaderTimeout:5*time.Second,
		ReadTimeout:10*time.Second,
		WriteTimeout:15*time.Second,
		IdleTimeout:60*time.Second,
	}
	log.Fatal(httpServer.ListenAndServe())
}

func buildMailSender() maildelivery.Sender {
	addr:=strings.TrimSpace(os.Getenv("GATEKEEPER_SMTP_ADDR"))
	if addr=="" { return nil }
	return maildelivery.SMTP{
		Addr:addr,
		Username:os.Getenv("GATEKEEPER_SMTP_USERNAME"),
		Password:os.Getenv("GATEKEEPER_SMTP_PASSWORD"),
		From:env("GATEKEEPER_SMTP_FROM","gatekeeper@example.test"),
	}
}

func developmentAccessRules() []access.Rule {
	rules:=[]access.Rule{}
	if value:=strings.TrimSpace(os.Getenv("GATEKEEPER_ALLOWED_EMAIL"));value!=""{rules=append(rules,access.Rule{Type:access.RuleEmail,Value:value})}
	if value:=strings.TrimSpace(os.Getenv("GATEKEEPER_ALLOWED_DOMAIN"));value!=""{rules=append(rules,access.Rule{Type:access.RuleDomain,Value:value})}
	return rules
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
