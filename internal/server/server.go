package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Config struct {
	AllowedEmail string
	CookieName string
	CookieSecure bool
	DeviceLifetime time.Duration
}

type challenge struct {
	Email string
	Code string
	ReturnURL string
	ExpiresAt time.Time
}

type device struct {
	Email string
	ExpiresAt time.Time
}

type Server struct {
	config Config
	mu sync.Mutex
	challenges map[string]challenge
	devices map[string]device
}

func New(config Config) *Server {
	return &Server{config: config, challenges: make(map[string]challenge), devices: make(map[string]device)}
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
	if cookie, err := r.Cookie(s.config.CookieName); err == nil && s.validDevice(cookie.Value) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, "/.gatekeeper/login?return="+url.QueryEscape(originalURL(r)), http.StatusFound)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	render(w, loginTemplate, map[string]string{"ReturnURL": safeReturnURL(r.URL.Query().Get("return"))})
}

func (s *Server) startChallenge(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil { http.Error(w, "Invalid request", http.StatusBadRequest); return }
	email := strings.TrimSpace(strings.ToLower(r.FormValue("email")))
	returnURL := safeReturnURL(r.FormValue("return"))

	// Do not reveal whether an address is authorised.
	if subtle.ConstantTimeCompare([]byte(email), []byte(strings.ToLower(s.config.AllowedEmail))) != 1 {
		render(w, sentTemplate, nil)
		return
	}

	id, code := randomToken(24), randomCode()
	s.mu.Lock()
	s.challenges[id] = challenge{Email: email, Code: code, ReturnURL: returnURL, ExpiresAt: time.Now().Add(10 * time.Minute)}
	s.mu.Unlock()
	log.Printf("development OTP for %s: %s", email, code)
	http.Redirect(w, r, "/.gatekeeper/verify?id="+url.QueryEscape(id), http.StatusFound)
}

func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	s.mu.Lock()
	ch, ok := s.challenges[id]
	s.mu.Unlock()
	if !ok || time.Now().After(ch.ExpiresAt) { http.Error(w, "This access code has expired.", http.StatusUnauthorized); return }
	render(w, verifyTemplate, map[string]string{"ID": id})
}

func (s *Server) completeChallenge(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil { http.Error(w, "Invalid request", http.StatusBadRequest); return }
	id, code := r.FormValue("id"), strings.TrimSpace(r.FormValue("code"))

	s.mu.Lock()
	ch, ok := s.challenges[id]
	if !ok || time.Now().After(ch.ExpiresAt) || subtle.ConstantTimeCompare([]byte(code), []byte(ch.Code)) != 1 {
		s.mu.Unlock()
		http.Error(w, "Invalid or expired access code.", http.StatusUnauthorized)
		return
	}
	delete(s.challenges, id)
	token := randomToken(32)
	s.devices[token] = device{Email: ch.Email, ExpiresAt: time.Now().Add(s.config.DeviceLifetime)}
	s.mu.Unlock()

	http.SetCookie(w, &http.Cookie{Name: s.config.CookieName, Value: token, Path: "/", HttpOnly: true, Secure: s.config.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: int(s.config.DeviceLifetime.Seconds())})
	http.Redirect(w, r, ch.ReturnURL, http.StatusFound)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(s.config.CookieName); err == nil {
		s.mu.Lock(); delete(s.devices, cookie.Value); s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: s.config.CookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.config.CookieSecure, SameSite: http.SameSiteLaxMode})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) validDevice(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[token]
	if !ok || time.Now().After(d.ExpiresAt) { delete(s.devices, token); return false }
	d.ExpiresAt = time.Now().Add(s.config.DeviceLifetime)
	s.devices[token] = d
	return true
}

func originalURL(r *http.Request) string {
	uri := r.Header.Get("X-Forwarded-Uri")
	if uri == "" { uri = "/" }
	return safeReturnURL(uri)
}

func safeReturnURL(value string) string {
	if value == "" || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") { return "/" }
	return value
}

func randomToken(size int) string {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil { panic(err) }
	return base64.RawURLEncoding.EncodeToString(buf)
}

func randomCode() string {
	buf := make([]byte, 3)
	if _, err := rand.Read(buf); err != nil { panic(err) }
	n := (int(buf[0])<<16 | int(buf[1])<<8 | int(buf[2])) % 1000000
	return fmt.Sprintf("%06d", n)
}

func render(w http.ResponseWriter, source string, data any) {
	t := template.Must(template.New("page").Parse(source))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = t.Execute(w, data)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

const style = "<style>body{font-family:system-ui,sans-serif;background:#f5f6f8;color:#20242a;margin:0}main{max-width:28rem;margin:12vh auto;background:white;padding:2rem;border-radius:.75rem;box-shadow:0 8px 30px #0001}h1{margin-top:0}label{display:block;margin:.75rem 0 .35rem}input{box-sizing:border-box;width:100%;padding:.8rem;font:inherit}button{margin-top:1rem;padding:.8rem 1rem;font:inherit;cursor:pointer}p{line-height:1.5;color:#505760}</style>"

const loginTemplate = "<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">"+style+"<title>Access required</title></head><body><main><h1>Access required</h1><p>Enter your authorised email address. If it has access, we'll send you a one-time code.</p><form method="post" action="/.gatekeeper/login"><input type="hidden" name="return" value="{{.ReturnURL}}"><label for="email">Email address</label><input id="email" name="email" type="email" autocomplete="email" required autofocus><button type="submit">Send access code</button></form></main></body></html>"
const verifyTemplate = "<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">"+style+"<title>Enter access code</title></head><body><main><h1>Check your email</h1><p>Enter the six-digit access code. It expires after 10 minutes.</p><form method="post" action="/.gatekeeper/verify"><input type="hidden" name="id" value="{{.ID}}"><label for="code">Access code</label><input id="code" name="code" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" required autofocus><button type="submit">Continue</button></form></main></body></html>"
const sentTemplate = "<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">"+style+"<title>Check your email</title></head><body><main><h1>Check your email</h1><p>If that address is authorised, an access code has been sent. You can safely close this page if you didn't request access.</p></main></body></html>"
