package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math/big"
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
	CodeHash [32]byte
	ReturnURL string
	ExpiresAt time.Time
	Attempts int
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

	authorised := subtle.ConstantTimeCompare([]byte(email), []byte(strings.ToLower(s.config.AllowedEmail))) == 1
	id, code := randomToken(24), randomCode()

	// Always create a challenge and follow the same browser flow. For an
	// unauthorised address the challenge is deliberately unverifiable.
	codeHash := hashValue(randomToken(32))
	if authorised {
		codeHash = hashValue(code)
	}

	s.mu.Lock()
	s.challenges[id] = challenge{Email: email, CodeHash: codeHash, ReturnURL: returnURL, ExpiresAt: time.Now().Add(10 * time.Minute)}
	s.mu.Unlock()
	if authorised {
		log.Printf("development OTP for %s: %s", email, code)
	}
	http.Redirect(w, r, "/.gatekeeper/verify?id="+url.QueryEscape(id), http.StatusFound)
}

func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	s.mu.Lock()
	ch, ok := s.challenges[id]
	s.mu.Unlock()
	if !ok || time.Now().After(ch.ExpiresAt) { s.expireChallenge(id); render(w, expiredTemplate, nil); return }
	render(w, verifyTemplate, map[string]string{"ID": id})
}

func (s *Server) completeChallenge(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil { http.Error(w, "Invalid request", http.StatusBadRequest); return }
	id, code := r.FormValue("id"), strings.TrimSpace(r.FormValue("code"))

	s.mu.Lock()
	ch, ok := s.challenges[id]
	if !ok || time.Now().After(ch.ExpiresAt) {
		delete(s.challenges, id)
		s.mu.Unlock()
		render(w, expiredTemplate, nil)
		return
	}
	if subtle.ConstantTimeCompare(hashBytes(code), ch.CodeHash[:]) != 1 {
		ch.Attempts++
		if ch.Attempts >= 5 {
			delete(s.challenges, id)
			s.mu.Unlock()
			render(w, expiredTemplate, nil)
			return
		}
		s.challenges[id] = ch
		s.mu.Unlock()
		render(w, invalidCodeTemplate, map[string]any{"ID": id, "AttemptsLeft": 5 - ch.Attempts})
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
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil { panic(err) }
	return fmt.Sprintf("%06d", n.Int64())
}

func hashValue(value string) [32]byte {
	return sha256.Sum256([]byte(value))
}

func hashBytes(value string) []byte {
	h := hashValue(value)
	return h[:]
}

func (s *Server) expireChallenge(id string) {
	s.mu.Lock()
	delete(s.challenges, id)
	s.mu.Unlock()
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

const loginTemplate = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">`+style+`<title>Access required</title></head><body><main><h1>Access required</h1><p>Enter your authorised email address. If it has access, we'll send you a one-time code.</p><form method="post" action="/.gatekeeper/login"><input type="hidden" name="return" value="{{.ReturnURL}}"><label for="email">Email address</label><input id="email" name="email" type="email" autocomplete="email" required autofocus><button type="submit">Send access code</button></form></main></body></html>`
const verifyTemplate = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">`+style+`<title>Enter access code</title></head><body><main><h1>Check your email</h1><p>Enter the access code from your email. It expires after 10 minutes.</p><form method="post" action="/.gatekeeper/verify"><input type="hidden" name="id" value="{{.ID}}"><label for="code">Access code</label><input id="code" name="code" autocomplete="one-time-code" required autofocus><button type="submit">Continue</button></form></main></body></html>`
const invalidCodeTemplate = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">`+style+`<title>Invalid access code</title></head><body><main><h1>That code was not accepted</h1><p>Please check the code and try again. You have {{.AttemptsLeft}} attempts remaining.</p><form method="post" action="/.gatekeeper/verify"><input type="hidden" name="id" value="{{.ID}}"><label for="code">Access code</label><input id="code" name="code" autocomplete="one-time-code" required autofocus><button type="submit">Continue</button></form></main></body></html>`
const expiredTemplate = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">`+style+`<title>Request a new code</title></head><body><main><h1>Request a new code</h1><p>This access challenge has expired or can no longer be used.</p><p><a href="/.gatekeeper/login">Start again</a></p></main></body></html>`
