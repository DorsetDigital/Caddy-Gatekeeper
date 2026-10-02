package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/identity"
	maildelivery "github.com/DorsetDigital/Caddy-Gatekeeper/internal/mail"
	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/management"
	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/ratelimit"
	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/server"
	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/site"
	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/store"
)

func main() {
	if err:=run();err!=nil {
		log.Fatal(err)
	}
}

func run() error {
	addr := env("GATEKEEPER_LISTEN", ":9080")
	state, err := buildStore(context.Background())
	if err != nil { return fmt.Errorf("initialise state store: %w", err) }
	defer state.Close()

	var sites site.Repository
	var limiter ratelimit.Limiter
	if valkeyStore,ok:=state.(*store.Valkey);ok{
		sites=site.NewValkey(valkeyStore.Client(),valkeyStore.Prefix())
		limiter=ratelimit.NewValkey(valkeyStore.Client(),valkeyStore.Prefix())
	}else{
		sites=site.NewMemory()
		limiter=ratelimit.NewMemory()
	}

	apiAddr:=env("GATEKEEPER_API_LISTEN",":9081")
	api:=management.New(sites,requiredEnv("GATEKEEPER_API_TOKEN"))
	apiServer:=&http.Server{
		Addr:apiAddr,
		Handler:api.Handler(),
		ReadHeaderTimeout:5*time.Second,
		ReadTimeout:10*time.Second,
		WriteTimeout:15*time.Second,
		IdleTimeout:60*time.Second,
	}

	dispatcher:=buildMailDispatcher()

	app := server.New(server.Config{
		Sites: sites,
		CookieName: "gatekeeper_device",
		CookieSecure: env("GATEKEEPER_COOKIE_SECURE", "false") == "true",
		DeviceLifetime: 30 * 24 * time.Hour,
		MaxAttempts: envInt("GATEKEEPER_MAX_ATTEMPTS", 3),
		IdentityHasher: identity.NewHasher(requiredEnv("GATEKEEPER_IDENTITY_KEY")),
		Store: state,
		MailDispatcher: dispatcher,
		StateTimeout: envDuration("GATEKEEPER_STATE_TIMEOUT", time.Second),
		RateLimiter: limiter,
		SiteRateLimit: envInt("GATEKEEPER_SITE_RATE_LIMIT", 10),
		SiteRateWindow: envDuration("GATEKEEPER_SITE_RATE_WINDOW", 10*time.Minute),
		IdentityRateLimit: envInt("GATEKEEPER_IDENTITY_RATE_LIMIT", 2),
		IdentityRateWindow: envDuration("GATEKEEPER_IDENTITY_RATE_WINDOW", 10*time.Minute),
	})

	httpServer:=&http.Server{
		Addr:addr,
		Handler:app.Handler(),
		ReadHeaderTimeout:5*time.Second,
		ReadTimeout:10*time.Second,
		WriteTimeout:15*time.Second,
		IdleTimeout:60*time.Second,
	}

	serverErrors:=make(chan error,2)
	startServer:=func(name string,srv *http.Server){
		go func(){
			if err:=srv.ListenAndServe();err!=nil&&!errors.Is(err,http.ErrServerClosed){
				serverErrors<-fmt.Errorf("%s: %w",name,err)
			}
		}()
	}

	log.Printf("caddy-gatekeeper management API listening on %s",apiAddr)
	startServer("management API",apiServer)
	log.Printf("caddy-gatekeeper listening on %s",addr)
	startServer("authentication server",httpServer)

	signalCtx,stopSignals:=signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM)
	defer stopSignals()

	var runErr error
	select{
	case <-signalCtx.Done():
		log.Printf("caddy-gatekeeper shutdown requested")
	case runErr=<-serverErrors:
		log.Printf("caddy-gatekeeper server failure: %v",runErr)
	}

	shutdownTimeout:=envDuration("GATEKEEPER_SHUTDOWN_TIMEOUT",15*time.Second)
	shutdownCtx,cancel:=context.WithTimeout(context.Background(),shutdownTimeout)
	defer cancel()

	var wg sync.WaitGroup
	shutdownErrors:=make(chan error,2)
	shutdownServer:=func(name string,srv *http.Server){
		defer wg.Done()
		if err:=srv.Shutdown(shutdownCtx);err!=nil{
			_ = srv.Close()
			shutdownErrors<-fmt.Errorf("%s shutdown: %w",name,err)
		}
	}

	wg.Add(2)
	go shutdownServer("authentication server",httpServer)
	go shutdownServer("management API",apiServer)
	wg.Wait()
	close(shutdownErrors)

	var shutdownErr error
	for err:=range shutdownErrors{
		shutdownErr=errors.Join(shutdownErr,err)
	}

	if dispatcher!=nil{
		if err:=dispatcher.Shutdown(shutdownCtx);err!=nil{
			shutdownErr=errors.Join(shutdownErr,fmt.Errorf("SMTP dispatcher shutdown: %w",err))
		}
	}

	if shutdownErr!=nil{
		log.Printf("caddy-gatekeeper shutdown completed with errors: %v",shutdownErr)
	}else{
		log.Printf("caddy-gatekeeper shutdown complete")
	}

	if runErr!=nil{return runErr}
	return shutdownErr
}

func buildMailDispatcher() maildelivery.Dispatcher {
	addr:=strings.TrimSpace(os.Getenv("GATEKEEPER_SMTP_ADDR"))
	if addr=="" { return nil }
	sender:=maildelivery.SMTP{
		Addr:addr,
		Username:os.Getenv("GATEKEEPER_SMTP_USERNAME"),
		Password:os.Getenv("GATEKEEPER_SMTP_PASSWORD"),
		From:env("GATEKEEPER_SMTP_FROM","gatekeeper@example.test"),
	}
	return maildelivery.NewAsyncDispatcher(
		sender,
		envInt("GATEKEEPER_SMTP_WORKERS",2),
		envInt("GATEKEEPER_SMTP_QUEUE_SIZE",20),
		envDuration("GATEKEEPER_SMTP_DELIVERY_TIMEOUT",10*time.Second),
	)
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
		DialTimeout:envDuration("GATEKEEPER_VALKEY_DIAL_TIMEOUT",750*time.Millisecond),
		ReadTimeout:envDuration("GATEKEEPER_VALKEY_READ_TIMEOUT",750*time.Millisecond),
		WriteTimeout:envDuration("GATEKEEPER_VALKEY_WRITE_TIMEOUT",750*time.Millisecond),
		PoolTimeout:envDuration("GATEKEEPER_VALKEY_POOL_TIMEOUT",750*time.Millisecond),
	})
}
func requiredEnv(name string) string { value:=os.Getenv(name);if value==""{log.Fatalf("%s is required",name)};return value }
func envInt(name string,fallback int)int{value:=os.Getenv(name);if value==""{return fallback};parsed,err:=strconv.Atoi(value);if err!=nil||parsed<1{log.Fatalf("%s must be a positive integer",name)};return parsed}
func envDuration(name string,fallback time.Duration)time.Duration{value:=os.Getenv(name);if value==""{return fallback};parsed,err:=time.ParseDuration(value);if err!=nil||parsed<=0{log.Fatalf("%s must be a positive duration",name)};return parsed}
func env(name,fallback string)string{if value:=os.Getenv(name);value!=""{return value};return fallback}
