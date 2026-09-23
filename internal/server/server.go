package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"html/template"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/access"
	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/identity"
	maildelivery "github.com/DorsetDigital/Caddy-Gatekeeper/internal/mail"
	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/ratelimit"
	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/site"
	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/store"
)

type Config struct {
	AccessMatcher access.Matcher
	Sites site.Repository
	CookieName string
	CookieSecure bool
	DeviceLifetime time.Duration
	DeviceRefreshInterval time.Duration
	ChallengeLifetime time.Duration
	MaxAttempts int
	IdentityHasher identity.Hasher
	Store store.Store
	MailDispatcher maildelivery.Dispatcher
	StateTimeout time.Duration
	RateLimiter ratelimit.Limiter
	SiteRateLimit int
	SiteRateWindow time.Duration
	IdentityRateLimit int
	IdentityRateWindow time.Duration
}

type Server struct { config Config }

func New(config Config) *Server {
	if config.Store == nil { config.Store = store.NewMemory() }
	if config.ChallengeLifetime == 0 { config.ChallengeLifetime = 10 * time.Minute }
	if config.DeviceRefreshInterval == 0 { config.DeviceRefreshInterval = 24 * time.Hour }
	if config.MaxAttempts == 0 { config.MaxAttempts = 3 }
	if config.StateTimeout == 0 { config.StateTimeout = time.Second }
	if config.SiteRateLimit == 0 { config.SiteRateLimit = 10 }
	if config.SiteRateWindow == 0 { config.SiteRateWindow = 10 * time.Minute }
	if config.IdentityRateLimit == 0 { config.IdentityRateLimit = 2 }
	if config.IdentityRateWindow == 0 { config.IdentityRateWindow = 10 * time.Minute }
	return &Server{config: config}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("GET /ready", s.ready)
	mux.HandleFunc("GET /auth/check", s.check)
	mux.HandleFunc("GET /login", s.login)
	mux.HandleFunc("POST /login", s.startChallenge)
	mux.HandleFunc("GET /verify", s.verify)
	mux.HandleFunc("POST /verify", s.completeChallenge)
	mux.HandleFunc("POST /logout", s.logout)
	return securityHeaders(s.withStateTimeout(mux))
}

func (s *Server) withStateTimeout(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), s.config.StateTimeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if s.config.Sites != nil {
		if _, err := s.config.Sites.List(r.Context()); err != nil {
			http.Error(w, "Gatekeeper state unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) check(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(s.config.CookieName); err == nil {
		ok, refreshCookie, storeErr := s.validDevice(r.Context(), cookie.Value, r.Host)
		if storeErr != nil { http.Error(w, "Gatekeeper state unavailable", http.StatusServiceUnavailable); return }
		if ok {
			if refreshCookie { s.setDeviceCookie(w, cookie.Value) }
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	http.Redirect(w, r, "/.gatekeeper/login?return="+url.QueryEscape(originalURL(r)), http.StatusFound)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	render(w, loginTemplate, map[string]string{"ReturnURL": safeReturnURL(r.URL.Query().Get("return")), "Host": displayHost(r.Host)})
}

func (s *Server) startChallenge(w http.ResponseWriter, r *http.Request) {
	r.Body=http.MaxBytesReader(w,r.Body,16<<10)
	if err := r.ParseForm(); err != nil { http.Error(w, "Invalid request", http.StatusBadRequest); return }
	email := normaliseIdentity(r.FormValue("email"))
	returnURL := safeReturnURL(r.FormValue("return"))
	matcher:=s.config.AccessMatcher
	var siteID string
	if s.config.Sites!=nil {
		configured,err:=s.config.Sites.GetByHost(r.Context(),r.Host)
		if err!=nil&&!errors.Is(err,site.ErrNotFound){http.Error(w,"Gatekeeper configuration unavailable",http.StatusServiceUnavailable);return}
		if errors.Is(err,site.ErrNotFound){matcher=access.NewMatcher(nil)}else{matcher=access.NewMatcher(configured.AccessRules);siteID=configured.ID}
	}
	identityID := s.config.IdentityHasher.ID(email)
	if !s.allowOTPRequest(w,r,siteID,identityID) { return }
	authorised := matcher.Allowed(email)
	id,err:=randomToken(24)
	if err!=nil{http.Error(w,"Gatekeeper entropy unavailable",http.StatusServiceUnavailable);return}
	code,err:=randomCode()
	if err!=nil{http.Error(w,"Gatekeeper entropy unavailable",http.StatusServiceUnavailable);return}
	fakeSecret,err:=randomToken(32)
	if err!=nil{http.Error(w,"Gatekeeper entropy unavailable",http.StatusServiceUnavailable);return}
	codeHash := hashValue(fakeSecret)
	if authorised { codeHash = hashValue(code) }

	ch := store.Challenge{SiteID: siteID, IdentityID: identityID, CodeHash: codeHash[:], ReturnURL: returnURL}
	if err := s.config.Store.CreateChallenge(r.Context(), id, ch, s.config.ChallengeLifetime); err != nil {
		http.Error(w, "Gatekeeper state unavailable", http.StatusServiceUnavailable); return
	}
	if authorised && s.config.MailDispatcher != nil {
		message:=maildelivery.OTPMessage(email,r.Host,code)
		message.SiteID=siteID
		if err:=s.config.MailDispatcher.Enqueue(message);err!=nil {
			if errors.Is(err,maildelivery.ErrQueueFull) {
				log.Printf("gatekeeper: OTP delivery queue full site=%q host=%q",siteID,r.Host)
			} else {
				log.Printf("gatekeeper: OTP delivery enqueue failed site=%q host=%q: %v",siteID,r.Host,err)
			}
		} else {
			log.Printf("gatekeeper: OTP delivery queued site=%q host=%q",siteID,r.Host)
		}
	}
	http.Redirect(w, r, "/.gatekeeper/verify?id="+url.QueryEscape(id), http.StatusFound)
}


func (s *Server) allowOTPRequest(w http.ResponseWriter, r *http.Request, siteID, identityID string) bool {
	if s.config.RateLimiter == nil || siteID == "" {
		return true
	}

	checks := []struct {
		key    string
		limit  int
		window time.Duration
		kind   string
	}{
		{key: "site:" + siteID, limit: s.config.SiteRateLimit, window: s.config.SiteRateWindow, kind: "site"},
		{key: "identity:" + siteID + ":" + identityID, limit: s.config.IdentityRateLimit, window: s.config.IdentityRateWindow, kind: "identity"},
	}

	for _, check := range checks {
		result, err := s.config.RateLimiter.Allow(r.Context(), check.key, check.limit, check.window)
		if err != nil {
			http.Error(w, "Gatekeeper state unavailable", http.StatusServiceUnavailable)
			return false
		}
		if result.Allowed {
			continue
		}

		if result.FirstBlocked {
			if check.kind == "site" {
				log.Printf("gatekeeper: OTP site rate limit reached site=%q host=%q window=%s", siteID, r.Host, check.window)
			} else {
				shortID := identityID
				if len(shortID) > 8 {
					shortID = shortID[:8]
				}
				log.Printf("gatekeeper: OTP identity rate limit reached site=%q host=%q identity=%q window=%s", siteID, r.Host, shortID, check.window)
			}
		}

		retrySeconds := int((result.RetryAfter + time.Second - 1) / time.Second)
		if retrySeconds < 1 {
			retrySeconds = 1
		}
		w.Header().Set("Retry-After", fmt.Sprintf("%d", retrySeconds))
		http.Error(w, "Too many access-code requests. Please try again shortly.", http.StatusTooManyRequests)
		return false
	}

	return true
}

func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	_, err := s.config.Store.GetChallenge(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) { render(w, expiredTemplate, map[string]string{"ReturnURL": "/", "Host": displayHost(r.Host)}); return }
	if err != nil { http.Error(w, "Gatekeeper state unavailable", http.StatusServiceUnavailable); return }
	render(w, verifyTemplate, map[string]string{"ID": id, "Host": displayHost(r.Host)})
}

func (s *Server) completeChallenge(w http.ResponseWriter, r *http.Request) {
	r.Body=http.MaxBytesReader(w,r.Body,16<<10)
	if err := r.ParseForm(); err != nil { http.Error(w, "Invalid request", http.StatusBadRequest); return }
	id, code := r.FormValue("id"), strings.TrimSpace(r.FormValue("code"))
	result, err := s.config.Store.VerifyChallenge(r.Context(), id, hashBytes(code), s.config.MaxAttempts)
	if err != nil { http.Error(w, "Gatekeeper state unavailable", http.StatusServiceUnavailable); return }
	switch result.Status {
	case store.VerifyNotFound:
		render(w, expiredTemplate, map[string]string{"ReturnURL": "/", "Host": displayHost(r.Host)})
		return
	case store.VerifyInvalid:
		render(w, invalidCodeTemplate, map[string]any{"ID": id, "AttemptsLeft": result.Remaining, "Host": displayHost(r.Host)})
		return
	case store.VerifyExhausted:
		render(w, expiredTemplate, map[string]string{"ReturnURL": result.Challenge.ReturnURL, "Host": displayHost(r.Host)})
		return
	case store.VerifySuccess:
		// Continue below with the challenge that was atomically consumed.
	default:
		http.Error(w, "Gatekeeper state unavailable", http.StatusServiceUnavailable)
		return
	}
	ch := result.Challenge

	token,err := randomToken(32)
	if err!=nil{http.Error(w,"Gatekeeper entropy unavailable",http.StatusServiceUnavailable);return}
	tokenHash := hashString(token)
	now := time.Now()
	if err := s.config.Store.CreateDevice(r.Context(), tokenHash, store.Device{SiteID: ch.SiteID, IdentityID: ch.IdentityID, LastSeen: now}, s.config.DeviceLifetime); err != nil {
		http.Error(w, "Gatekeeper state unavailable", http.StatusServiceUnavailable); return
	}
	s.setDeviceCookie(w, token)
	http.Redirect(w, r, ch.ReturnURL, http.StatusFound)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(s.config.CookieName); err == nil {
		if err := s.config.Store.DeleteDevice(r.Context(), hashString(cookie.Value)); err != nil { http.Error(w, "Gatekeeper state unavailable", http.StatusServiceUnavailable); return }
	}
	http.SetCookie(w,&http.Cookie{Name:s.config.CookieName,Value:"",Path:"/",MaxAge:-1,HttpOnly:true,Secure:s.config.CookieSecure,SameSite:http.SameSiteLaxMode})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) validDevice(ctx context.Context, token string, host string) (bool,bool,error) {
	key := hashString(token)
	d,err := s.config.Store.GetDevice(ctx,key)
	if errors.Is(err,store.ErrNotFound){return false,false,nil}
	if err != nil{return false,false,err}
	if s.config.Sites!=nil {
		configured,siteErr:=s.config.Sites.GetByHost(ctx,host)
		if errors.Is(siteErr,site.ErrNotFound)||siteErr==nil&&configured.ID!=d.SiteID{return false,false,nil}
		if siteErr!=nil{return false,false,siteErr}
	}
	if time.Since(d.LastSeen) >= s.config.DeviceRefreshInterval {
		d.LastSeen=time.Now()
		if err:=s.config.Store.RefreshDevice(ctx,key,d,s.config.DeviceLifetime);err!=nil{return false,false,err}
		return true,true,nil
	}
	return true,false,nil
}

func (s *Server) setDeviceCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name: s.config.CookieName,
		Value: token,
		Path: "/",
		HttpOnly: true,
		Secure: s.config.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge: int(s.config.DeviceLifetime.Seconds()),
	})
}

func originalURL(r *http.Request) string { uri:=r.Header.Get("X-Forwarded-Uri");if uri==""{uri="/"};return safeReturnURL(uri) }
func safeReturnURL(value string) string { if value==""||!strings.HasPrefix(value,"/")||strings.HasPrefix(value,"//"){return "/"};return value }
func normaliseIdentity(value string) string { return strings.ToLower(strings.TrimSpace(value)) }
func displayHost(hostport string) string {
	hostport = strings.TrimSpace(hostport)
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.ToLower(strings.TrimSuffix(host, "."))
	}
	return strings.ToLower(strings.TrimSuffix(hostport, "."))
}

var entropyReader io.Reader = rand.Reader

func randomToken(size int)(string,error){
	buf:=make([]byte,size)
	if _,err:=io.ReadFull(entropyReader,buf);err!=nil{return "",err}
	return base64.RawURLEncoding.EncodeToString(buf),nil
}
func randomCode()(string,error){
	n,err:=rand.Int(entropyReader,big.NewInt(1000000))
	if err!=nil{return "",err}
	return fmt.Sprintf("%06d",n.Int64()),nil
}
func hashValue(value string)[32]byte{return sha256.Sum256([]byte(value))}
func hashBytes(value string)[]byte{h:=hashValue(value);return h[:]}
func hashString(value string)string{return fmt.Sprintf("%x",hashValue(value))}

func render(w http.ResponseWriter,source string,data any){t:=template.Must(template.New("page").Parse(source));w.Header().Set("Content-Type","text/html; charset=utf-8");_ = t.Execute(w,data)}
func securityHeaders(next http.Handler)http.Handler{return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.Header().Set("X-Content-Type-Options","nosniff");w.Header().Set("X-Frame-Options","DENY");w.Header().Set("Referrer-Policy","no-referrer");w.Header().Set("Cache-Control","no-store");next.ServeHTTP(w,r)})}

const style=`<style>
:root{color-scheme:light;--ink:#111214;--muted:#656a73;--line:#e5e7eb;--panel:#fff;--page:#f3f4f6;--accent:#f2ff00}
*{box-sizing:border-box}
html,body{min-height:100%}
body{margin:0;background:var(--page);color:var(--ink);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
.shell{min-height:100vh;display:grid;place-items:center;padding:2rem 1rem}
.card{width:min(100%,32rem);background:var(--panel);border:1px solid var(--line);border-radius:1rem;box-shadow:0 18px 50px rgba(17,18,20,.08);overflow:hidden}
.brand{display:flex;align-items:center;justify-content:space-between;gap:1rem;padding:1.1rem 1.4rem;background:var(--ink);color:#fff}
.wordmark{font-weight:800;letter-spacing:-.035em;font-size:1.15rem}
.badge{width:.8rem;height:.8rem;border-radius:50%;background:var(--accent);box-shadow:0 0 0 .24rem rgba(242,255,0,.12)}
.content{padding:2rem}
.eyebrow{margin:0 0 .75rem;color:var(--muted);font-size:.78rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase}
h1{margin:0 0 .8rem;font-size:clamp(1.7rem,4vw,2.2rem);line-height:1.08;letter-spacing:-.035em}
p{margin:.6rem 0;line-height:1.55;color:var(--muted)}
.site{margin:1.4rem 0;padding:.9rem 1rem;border:1px solid var(--line);border-radius:.65rem;background:#fafafa;color:var(--ink);font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:.9rem;overflow-wrap:anywhere}
label{display:block;margin:1.3rem 0 .45rem;font-size:.9rem;font-weight:700}
input{width:100%;border:1px solid #cfd3d9;border-radius:.55rem;padding:.85rem .9rem;font:inherit;background:#fff;color:var(--ink);outline:none}
input:focus{border-color:var(--ink);box-shadow:0 0 0 3px rgba(17,18,20,.08)}
button,.button{display:inline-flex;align-items:center;justify-content:center;margin-top:1rem;border:0;border-radius:.55rem;background:var(--ink);color:#fff;padding:.82rem 1rem;font:inherit;font-weight:700;text-decoration:none;cursor:pointer}
button:hover,.button:hover{background:#2a2c30}
.meta{margin-top:1.6rem;padding-top:1.15rem;border-top:1px solid var(--line);font-size:.82rem;color:#7b8088}
.meta a{color:inherit}
.code input{font-size:1.25rem;letter-spacing:.22em;text-align:center;font-variant-numeric:tabular-nums}
.notice{margin:1rem 0;padding:.8rem .9rem;border-radius:.55rem;background:#f6f6f6;color:var(--ink);font-size:.9rem}
</style>`

const loginTemplate=`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Security check · {{.Host}}</title>`+style+`</head><body><div class="shell"><main class="card"><div class="brand"><span class="wordmark">Biff Bang Pow.</span><span class="badge" aria-hidden="true"></span></div><div class="content"><p class="eyebrow">Secure website access</p><h1>Confirm your email address</h1><p>This area is protected by Biff Bang Pow before you continue to the website administration system.</p><div class="site">https://{{.Host}}</div><p>Enter your authorised email address. If it has access, we'll send a one-time code.</p><form method="post" action="/.gatekeeper/login"><input type="hidden" name="return" value="{{.ReturnURL}}"><label for="email">Email address</label><input id="email" name="email" type="email" autocomplete="email" inputmode="email" required autofocus><button type="submit">Send access code</button></form><div class="meta">Security check provided by Biff Bang Pow.</div></div></main></div></body></html>`

const verifyTemplate=`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Enter access code · {{.Host}}</title>`+style+`</head><body><div class="shell"><main class="card"><div class="brand"><span class="wordmark">Biff Bang Pow.</span><span class="badge" aria-hidden="true"></span></div><div class="content"><p class="eyebrow">Secure website access</p><h1>Check your email</h1><div class="site">https://{{.Host}}</div><p>If the address is authorised, a six-digit access code has been sent. Enter it below to continue. Codes expire after 10 minutes.</p><form class="code" method="post" action="/.gatekeeper/verify"><input type="hidden" name="id" value="{{.ID}}"><label for="code">Access code</label><input id="code" name="code" inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code" maxlength="6" required autofocus><button type="submit">Continue</button></form><div class="meta">Security check provided by Biff Bang Pow.</div></div></main></div></body></html>`

const invalidCodeTemplate=`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Access code not accepted · {{.Host}}</title>`+style+`</head><body><div class="shell"><main class="card"><div class="brand"><span class="wordmark">Biff Bang Pow.</span><span class="badge" aria-hidden="true"></span></div><div class="content"><p class="eyebrow">Secure website access</p><h1>That code wasn't accepted</h1><div class="site">https://{{.Host}}</div><div class="notice">Check the code and try again. You have {{.AttemptsLeft}} attempts remaining.</div><form class="code" method="post" action="/.gatekeeper/verify"><input type="hidden" name="id" value="{{.ID}}"><label for="code">Access code</label><input id="code" name="code" inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code" maxlength="6" required autofocus><button type="submit">Try again</button></form><div class="meta">Security check provided by Biff Bang Pow.</div></div></main></div></body></html>`

const expiredTemplate=`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Access check expired · {{.Host}}</title>`+style+`</head><body><div class="shell"><main class="card"><div class="brand"><span class="wordmark">Biff Bang Pow.</span><span class="badge" aria-hidden="true"></span></div><div class="content"><p class="eyebrow">Secure website access</p><h1>Request a new code</h1><div class="site">https://{{.Host}}</div><p>This security check has expired or can no longer be used. Start again to request a new access code.</p><a class="button" href="/.gatekeeper/login?return={{urlquery .ReturnURL}}">Start again</a><div class="meta">Security check provided by Biff Bang Pow.</div></div></main></div></body></html>`

