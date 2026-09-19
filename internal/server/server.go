package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/identity"
	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/store"
)

type Config struct {
	AllowedEmail string
	CookieName string
	CookieSecure bool
	DeviceLifetime time.Duration
	DeviceRefreshInterval time.Duration
	ChallengeLifetime time.Duration
	MaxAttempts int
	IdentityHasher identity.Hasher
	Store store.Store
}

type Server struct { config Config }

func New(config Config) *Server {
	if config.Store == nil { config.Store = store.NewMemory() }
	if config.ChallengeLifetime == 0 { config.ChallengeLifetime = 10 * time.Minute }
	if config.DeviceRefreshInterval == 0 { config.DeviceRefreshInterval = 24 * time.Hour }
	if config.MaxAttempts == 0 { config.MaxAttempts = 3 }
	return &Server{config: config}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("GET /auth/check", s.check)
	mux.HandleFunc("GET /login", s.login)
	mux.HandleFunc("POST /login", s.startChallenge)
	mux.HandleFunc("GET /verify", s.verify)
	mux.HandleFunc("POST /verify", s.completeChallenge)
	mux.HandleFunc("POST /logout", s.logout)
	return securityHeaders(mux)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }

func (s *Server) check(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(s.config.CookieName); err == nil {
		ok, storeErr := s.validDevice(r.Context(), cookie.Value)
		if storeErr != nil { http.Error(w, "Gatekeeper state unavailable", http.StatusServiceUnavailable); return }
		if ok { w.WriteHeader(http.StatusNoContent); return }
	}
	http.Redirect(w, r, "/.gatekeeper/login?return="+url.QueryEscape(originalURL(r)), http.StatusFound)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	render(w, loginTemplate, map[string]string{"ReturnURL": safeReturnURL(r.URL.Query().Get("return"))})
}

func (s *Server) startChallenge(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil { http.Error(w, "Invalid request", http.StatusBadRequest); return }
	email := normaliseIdentity(r.FormValue("email"))
	returnURL := safeReturnURL(r.FormValue("return"))
	authorised := email == normaliseIdentity(s.config.AllowedEmail)
	id, code := randomToken(24), randomCode()
	codeHash := hashValue(randomToken(32))
	if authorised { codeHash = hashValue(code) }

	ch := store.Challenge{IdentityID: s.config.IdentityHasher.ID(email), CodeHash: codeHash[:], ReturnURL: returnURL}
	if err := s.config.Store.CreateChallenge(r.Context(), id, ch, s.config.ChallengeLifetime); err != nil {
		http.Error(w, "Gatekeeper state unavailable", http.StatusServiceUnavailable); return
	}
	if authorised { log.Printf("development OTP for %s: %s", email, code) }
	http.Redirect(w, r, "/.gatekeeper/verify?id="+url.QueryEscape(id), http.StatusFound)
}

func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	_, err := s.config.Store.GetChallenge(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) { render(w, expiredTemplate, map[string]string{"ReturnURL": "/"}); return }
	if err != nil { http.Error(w, "Gatekeeper state unavailable", http.StatusServiceUnavailable); return }
	render(w, verifyTemplate, map[string]string{"ID": id})
}

func (s *Server) completeChallenge(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil { http.Error(w, "Invalid request", http.StatusBadRequest); return }
	id, code := r.FormValue("id"), strings.TrimSpace(r.FormValue("code"))
	result, err := s.config.Store.VerifyChallenge(r.Context(), id, hashBytes(code), s.config.MaxAttempts)
	if err != nil { http.Error(w, "Gatekeeper state unavailable", http.StatusServiceUnavailable); return }
	switch result.Status {
	case store.VerifyNotFound:
		render(w, expiredTemplate, map[string]string{"ReturnURL": "/"})
		return
	case store.VerifyInvalid:
		render(w, invalidCodeTemplate, map[string]any{"ID": id, "AttemptsLeft": result.Remaining})
		return
	case store.VerifyExhausted:
		render(w, expiredTemplate, map[string]string{"ReturnURL": result.Challenge.ReturnURL})
		return
	case store.VerifySuccess:
		// Continue below with the challenge that was atomically consumed.
	default:
		http.Error(w, "Gatekeeper state unavailable", http.StatusServiceUnavailable)
		return
	}
	ch := result.Challenge

	token := randomToken(32)
	tokenHash := hashString(token)
	now := time.Now()
	if err := s.config.Store.CreateDevice(r.Context(), tokenHash, store.Device{IdentityID: ch.IdentityID, LastSeen: now}, s.config.DeviceLifetime); err != nil {
		http.Error(w, "Gatekeeper state unavailable", http.StatusServiceUnavailable); return
	}
	http.SetCookie(w, &http.Cookie{Name:s.config.CookieName,Value:token,Path:"/",HttpOnly:true,Secure:s.config.CookieSecure,SameSite:http.SameSiteLaxMode,MaxAge:int(s.config.DeviceLifetime.Seconds())})
	http.Redirect(w, r, ch.ReturnURL, http.StatusFound)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(s.config.CookieName); err == nil {
		if err := s.config.Store.DeleteDevice(r.Context(), hashString(cookie.Value)); err != nil { http.Error(w, "Gatekeeper state unavailable", http.StatusServiceUnavailable); return }
	}
	http.SetCookie(w,&http.Cookie{Name:s.config.CookieName,Value:"",Path:"/",MaxAge:-1,HttpOnly:true,Secure:s.config.CookieSecure,SameSite:http.SameSiteLaxMode})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) validDevice(ctx context.Context, token string) (bool,error) {
	key := hashString(token)
	d,err := s.config.Store.GetDevice(ctx,key)
	if errors.Is(err,store.ErrNotFound){return false,nil}
	if err != nil{return false,err}
	if time.Since(d.LastSeen) >= s.config.DeviceRefreshInterval {
		d.LastSeen=time.Now()
		if err:=s.config.Store.RefreshDevice(ctx,key,d,s.config.DeviceLifetime);err!=nil{return false,err}
	}
	return true,nil
}

func originalURL(r *http.Request) string { uri:=r.Header.Get("X-Forwarded-Uri");if uri==""{uri="/"};return safeReturnURL(uri) }
func safeReturnURL(value string) string { if value==""||!strings.HasPrefix(value,"/")||strings.HasPrefix(value,"//"){return "/"};return value }
func normaliseIdentity(value string) string { return strings.ToLower(strings.TrimSpace(value)) }
func randomToken(size int) string { buf:=make([]byte,size);if _,err:=rand.Read(buf);err!=nil{panic(err)};return base64.RawURLEncoding.EncodeToString(buf) }
func randomCode() string { n,err:=rand.Int(rand.Reader,big.NewInt(1000000));if err!=nil{panic(err)};return fmt.Sprintf("%06d",n.Int64()) }
func hashValue(value string)[32]byte{return sha256.Sum256([]byte(value))}
func hashBytes(value string)[]byte{h:=hashValue(value);return h[:]}
func hashString(value string)string{return fmt.Sprintf("%x",hashValue(value))}

func render(w http.ResponseWriter,source string,data any){t:=template.Must(template.New("page").Parse(source));w.Header().Set("Content-Type","text/html; charset=utf-8");_ = t.Execute(w,data)}
func securityHeaders(next http.Handler)http.Handler{return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.Header().Set("X-Content-Type-Options","nosniff");w.Header().Set("X-Frame-Options","DENY");w.Header().Set("Referrer-Policy","no-referrer");next.ServeHTTP(w,r)})}

const style="<style>body{font-family:system-ui,sans-serif;background:#f5f6f8;color:#20242a;margin:0}main{max-width:28rem;margin:12vh auto;background:white;padding:2rem;border-radius:.75rem;box-shadow:0 8px 30px #0001}h1{margin-top:0}label{display:block;margin:.75rem 0 .35rem}input{box-sizing:border-box;width:100%;padding:.8rem;font:inherit}button{margin-top:1rem;padding:.8rem 1rem;font:inherit;cursor:pointer}p{line-height:1.5;color:#505760}</style>"
const loginTemplate=`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">`+style+`<title>Access required</title></head><body><main><h1>Access required</h1><p>Enter your authorised email address. If it has access, we'll send you a one-time code.</p><form method="post" action="/.gatekeeper/login"><input type="hidden" name="return" value="{{.ReturnURL}}"><label for="email">Email address</label><input id="email" name="email" type="email" autocomplete="email" required autofocus><button type="submit">Send access code</button></form></main></body></html>`
const verifyTemplate=`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">`+style+`<title>Enter access code</title></head><body><main><h1>Check your email</h1><p>Enter the access code from your email. It expires after 10 minutes.</p><form method="post" action="/.gatekeeper/verify"><input type="hidden" name="id" value="{{.ID}}"><label for="code">Access code</label><input id="code" name="code" autocomplete="one-time-code" required autofocus><button type="submit">Continue</button></form></main></body></html>`
const invalidCodeTemplate=`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">`+style+`<title>Invalid access code</title></head><body><main><h1>That code was not accepted</h1><p>Please check the code and try again. You have {{.AttemptsLeft}} attempts remaining.</p><form method="post" action="/.gatekeeper/verify"><input type="hidden" name="id" value="{{.ID}}"><label for="code">Access code</label><input id="code" name="code" autocomplete="one-time-code" required autofocus><button type="submit">Continue</button></form></main></body></html>`
const expiredTemplate=`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">`+style+`<title>Request a new code</title></head><body><main><h1>Request a new code</h1><p>This access challenge has expired or can no longer be used.</p><p><a href="/.gatekeeper/login?return={{urlquery .ReturnURL}}">Start again</a></p></main></body></html>`
