package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	maildelivery "github.com/DorsetDigital/Caddy-Gatekeeper/internal/mail"

	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/access"
	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/identity"
	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/ratelimit"
	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/site"
	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/store"
)

type captureDispatcher struct { messages chan maildelivery.Message }
func (s *captureDispatcher) Enqueue(m maildelivery.Message) error { s.messages<-m;return nil }
func (s *captureDispatcher) Shutdown(context.Context) error { return nil }

type fullDispatcher struct{}
func (fullDispatcher) Enqueue(maildelivery.Message) error { return maildelivery.ErrQueueFull }
func (fullDispatcher) Shutdown(context.Context) error { return nil }

type blockingLimiter struct{}
func (blockingLimiter) Allow(ctx context.Context, _ string, _ int, _ time.Duration) (ratelimit.Result, error) {
	<-ctx.Done()
	return ratelimit.Result{}, ctx.Err()
}

func testServer() (*Server,*store.Memory) {
	st:=store.NewMemory()
	return New(Config{AccessMatcher:access.NewMatcher([]access.Rule{{Type:access.RuleEmail,Value:"developer@example.test"}}),CookieName:"gatekeeper_device",DeviceLifetime:30*24*time.Hour,MaxAttempts:3,IdentityHasher:identity.NewHasher("test-key"),Store:st}),st
}

func TestSafeReturnURL(t *testing.T){tests:=map[string]string{"":"/","/admin":"/admin","/admin?foo=bar":"/admin?foo=bar","https://evil.test/x":"/","//evil.test/x":"/"};for input,expected:=range tests{if actual:=safeReturnURL(input);actual!=expected{t.Fatalf("safeReturnURL(%q) = %q, want %q",input,actual,expected)}}}

func TestChallengeLockedAfterConfiguredBadCodes(t *testing.T){
	s,st:=testServer();id:="challenge";hash:=hashValue("123456")
	_ = st.CreateChallenge(context.Background(),id,store.Challenge{IdentityID:"identity",CodeHash:hash[:],ReturnURL:"/protected"},time.Minute)
	for attempt:=1;attempt<=3;attempt++{form:=url.Values{"id":{id},"code":{"000000"}};req:=httptest.NewRequest("POST","/verify",strings.NewReader(form.Encode()));req.Header.Set("Content-Type","application/x-www-form-urlencoded");res:=httptest.NewRecorder();s.completeChallenge(res,req)}
	if _,err:=st.GetChallenge(context.Background(),id);err==nil{t.Fatal("challenge still exists after configured failed attempts")}
}

func TestExhaustedChallengePreservesReturnURL(t *testing.T){
	s,st:=testServer();id:="challenge";hash:=hashValue("123456")
	_ = st.CreateChallenge(context.Background(),id,store.Challenge{IdentityID:"identity",CodeHash:hash[:],ReturnURL:"/admin/pages/edit/show/123"},time.Minute)
	for attempt:=1;attempt<=3;attempt++{form:=url.Values{"id":{id},"code":{"000000"}};req:=httptest.NewRequest("POST","/verify",strings.NewReader(form.Encode()));req.Header.Set("Content-Type","application/x-www-form-urlencoded");res:=httptest.NewRecorder();s.completeChallenge(res,req);if attempt==3&&!strings.Contains(res.Body.String(),"return=%2Fadmin%2Fpages%2Fedit%2Fshow%2F123"){t.Fatalf("start-again link lost original return URL: %s",res.Body.String())}}
}

func TestSuccessfulChallengeIsConsumedAndDeviceTokenIsHashed(t *testing.T){
	s,st:=testServer();id:="challenge";hash:=hashValue("123456")
	_ = st.CreateChallenge(context.Background(),id,store.Challenge{IdentityID:"identity",CodeHash:hash[:],ReturnURL:"/protected"},time.Minute)
	form:=url.Values{"id":{id},"code":{"123456"}};req:=httptest.NewRequest("POST","/verify",strings.NewReader(form.Encode()));req.Header.Set("Content-Type","application/x-www-form-urlencoded");res:=httptest.NewRecorder();s.completeChallenge(res,req)
	if _,err:=st.GetChallenge(context.Background(),id);err==nil{t.Fatal("challenge still exists after successful verification")}
	if res.Code!=302{t.Fatalf("status = %d, want 302",res.Code)}
	cookies:=res.Result().Cookies();if len(cookies)==0{t.Fatal("trusted-device cookie not set")}
	raw:=cookies[0].Value
	if _,err:=st.GetDevice(context.Background(),raw);err==nil{t.Fatal("raw browser credential was stored as device key")}
	if _,err:=st.GetDevice(context.Background(),hashString(raw));err!=nil{t.Fatal("hashed browser credential was not stored")}
}

func TestAuthorizedIdentityQueuesOTPEmail(t *testing.T){
	st:=store.NewMemory();sender:=&captureDispatcher{messages:make(chan maildelivery.Message,1)}
	s:=New(Config{AccessMatcher:access.NewMatcher([]access.Rule{{Type:access.RuleDomain,Value:"example.test"}}),CookieName:"gatekeeper_device",DeviceLifetime:time.Hour,MaxAttempts:3,IdentityHasher:identity.NewHasher("test-key"),Store:st,MailDispatcher:sender})
	form:=url.Values{"email":{"person@example.test"},"return":{"/protected"}}
	req:=httptest.NewRequest("POST","http://site.test/login",strings.NewReader(form.Encode()));req.Header.Set("Content-Type","application/x-www-form-urlencoded");res:=httptest.NewRecorder();s.startChallenge(res,req)
	if res.Code!=302{t.Fatalf("status=%d, want 302",res.Code)}
	select{case msg:=<-sender.messages:if msg.To!="person@example.test"{t.Fatalf("recipient=%q",msg.To)};case <-time.After(time.Second):t.Fatal("OTP email was not queued")}
}

func TestUnauthorizedIdentityDoesNotSendEmail(t *testing.T){
	st:=store.NewMemory();sender:=&captureDispatcher{messages:make(chan maildelivery.Message,1)}
	s:=New(Config{AccessMatcher:access.NewMatcher([]access.Rule{{Type:access.RuleDomain,Value:"example.test"}}),CookieName:"gatekeeper_device",DeviceLifetime:time.Hour,MaxAttempts:3,IdentityHasher:identity.NewHasher("test-key"),Store:st,MailDispatcher:sender})
	form:=url.Values{"email":{"person@other.test"},"return":{"/protected"}}
	req:=httptest.NewRequest("POST","http://site.test/login",strings.NewReader(form.Encode()));req.Header.Set("Content-Type","application/x-www-form-urlencoded");res:=httptest.NewRecorder();s.startChallenge(res,req)
	if res.Code!=302{t.Fatalf("status=%d, want 302",res.Code)}
	select{case <-sender.messages:t.Fatal("email sent for unauthorized identity");case <-time.After(50*time.Millisecond):}
}



func TestFullMailQueuePreservesChallengeFlow(t *testing.T){
	st:=store.NewMemory()
	s:=New(Config{
		AccessMatcher:access.NewMatcher([]access.Rule{{Type:access.RuleDomain,Value:"example.test"}}),
		CookieName:"gatekeeper_device",
		DeviceLifetime:time.Hour,
		MaxAttempts:3,
		IdentityHasher:identity.NewHasher("test-key"),
		Store:st,
		MailDispatcher:fullDispatcher{},
	})
	form:=url.Values{"email":{"person@example.test"},"return":{"/protected"}}
	req:=httptest.NewRequest("POST","http://site.test/login",strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type","application/x-www-form-urlencoded")
	res:=httptest.NewRecorder()
	s.startChallenge(res,req)

	if res.Code!=302{t.Fatalf("status=%d, want 302",res.Code)}
	if !strings.HasPrefix(res.Header().Get("Location"),"/.gatekeeper/verify?id="){
		t.Fatalf("location=%q, want verify challenge",res.Header().Get("Location"))
	}
}

func managedTestServer(t *testing.T)(*Server,*store.Memory,*site.Memory){
	t.Helper();st:=store.NewMemory();sites:=site.NewMemory()
	if err:=sites.Put(context.Background(),site.Site{ID:"a",Hosts:[]string{"a.test"},AccessRules:[]access.Rule{{Type:access.RuleDomain,Value:"a.test"}}});err!=nil{t.Fatal(err)}
	if err:=sites.Put(context.Background(),site.Site{ID:"b",Hosts:[]string{"b.test"},AccessRules:[]access.Rule{{Type:access.RuleDomain,Value:"b.test"}}});err!=nil{t.Fatal(err)}
	return New(Config{Sites:sites,CookieName:"gatekeeper_device",DeviceLifetime:time.Hour,MaxAttempts:3,IdentityHasher:identity.NewHasher("test-key"),Store:st}),st,sites
}

func TestUnknownManagedHostDoesNotUseLegacyMatcher(t *testing.T){
	st:=store.NewMemory();sites:=site.NewMemory();sender:=&captureDispatcher{messages:make(chan maildelivery.Message,1)}
	s:=New(Config{Sites:sites,AccessMatcher:access.NewMatcher([]access.Rule{{Type:access.RuleDomain,Value:"example.test"}}),CookieName:"gatekeeper_device",DeviceLifetime:time.Hour,MaxAttempts:3,IdentityHasher:identity.NewHasher("test-key"),Store:st,MailDispatcher:sender})
	form:=url.Values{"email":{"person@example.test"},"return":{"/protected"}}
	req:=httptest.NewRequest("POST","http://unknown.test/login",strings.NewReader(form.Encode()));req.Header.Set("Content-Type","application/x-www-form-urlencoded");res:=httptest.NewRecorder();s.startChallenge(res,req)
	if res.Code!=302{t.Fatalf("status=%d, want 302",res.Code)}
	select{case <-sender.messages:t.Fatal("unmanaged host used fallback access matcher");case <-time.After(50*time.Millisecond):}
}

func TestTrustedDeviceIsBoundToConfiguredSite(t *testing.T){
	s,st,_:=managedTestServer(t)
	token:="trusted-token";_ = st.CreateDevice(context.Background(),hashString(token),store.Device{SiteID:"a",IdentityID:"identity",LastSeen:time.Now()},time.Hour)
	if ok,_,err:=s.validDevice(context.Background(),token,"a.test");err!=nil||!ok{t.Fatalf("site A device rejected: ok=%v err=%v",ok,err)}
	if ok,_,err:=s.validDevice(context.Background(),token,"b.test");err!=nil||ok{t.Fatalf("site A device accepted on site B: ok=%v err=%v",ok,err)}
	if ok,_,err:=s.validDevice(context.Background(),token,"unknown.test");err!=nil||ok{t.Fatalf("site A device accepted on unknown host: ok=%v err=%v",ok,err)}
}

func TestSiteRuleUpdateTakesEffectImmediately(t *testing.T){
	s,_,sites:=managedTestServer(t);sender:=&captureDispatcher{messages:make(chan maildelivery.Message,2)};s.config.MailDispatcher=sender
	submit:=func(email string){form:=url.Values{"email":{email},"return":{"/protected"}};req:=httptest.NewRequest("POST","http://a.test/login",strings.NewReader(form.Encode()));req.Header.Set("Content-Type","application/x-www-form-urlencoded");res:=httptest.NewRecorder();s.startChallenge(res,req)}
	submit("person@a.test");select{case <-sender.messages:case <-time.After(time.Second):t.Fatal("initial site rule did not authorize")}
	if err:=sites.Put(context.Background(),site.Site{ID:"a",Hosts:[]string{"a.test"},AccessRules:[]access.Rule{{Type:access.RuleEmail,Value:"specific@a.test"}}});err!=nil{t.Fatal(err)}
	submit("person@a.test");select{case <-sender.messages:t.Fatal("old site rule remained active after update");case <-time.After(50*time.Millisecond):}
	submit("specific@a.test");select{case <-sender.messages:case <-time.After(time.Second):t.Fatal("updated site rule did not take effect")}
}

func TestDeletingSiteInvalidatesTrustedDevice(t *testing.T){
	s,st,sites:=managedTestServer(t);token:="trusted-token";_ = st.CreateDevice(context.Background(),hashString(token),store.Device{SiteID:"a",IdentityID:"identity",LastSeen:time.Now()},time.Hour)
	if err:=sites.Delete(context.Background(),"a");err!=nil{t.Fatal(err)}
	if ok,_,err:=s.validDevice(context.Background(),token,"a.test");err!=nil||ok{t.Fatalf("device remained valid after site deletion: ok=%v err=%v",ok,err)}
}

func TestTrustedDeviceRefreshReissuesBrowserCookie(t *testing.T){
	s,st,_:=managedTestServer(t)
	s.config.DeviceRefreshInterval=time.Hour
	s.config.DeviceLifetime=30*24*time.Hour
	token:="trusted-token"
	_ = st.CreateDevice(context.Background(),hashString(token),store.Device{SiteID:"a",IdentityID:"identity",LastSeen:time.Now().Add(-2*time.Hour)},s.config.DeviceLifetime)

	req:=httptest.NewRequest("GET","http://a.test/auth/check",nil)
	req.AddCookie(&http.Cookie{Name:s.config.CookieName,Value:token})
	res:=httptest.NewRecorder()
	s.check(res,req)

	if res.Code!=204{t.Fatalf("status=%d, want 204",res.Code)}
	cookies:=res.Result().Cookies()
	if len(cookies)!=1{t.Fatalf("Set-Cookie count=%d, want 1",len(cookies))}
	if cookies[0].Value!=token{t.Fatal("trusted-device token changed during sliding refresh")}
	if cookies[0].MaxAge!=int(s.config.DeviceLifetime.Seconds()){t.Fatalf("MaxAge=%d",cookies[0].MaxAge)}
}


func TestIdentityRateLimitBlocksThirdOTPRequest(t *testing.T){
	st:=store.NewMemory()
	sites:=site.NewMemory()
	if err:=sites.Put(context.Background(),site.Site{ID:"a",Hosts:[]string{"a.test"},AccessRules:[]access.Rule{{Type:access.RuleDomain,Value:"a.test"}}});err!=nil{t.Fatal(err)}
	s:=New(Config{
		Sites:sites,
		CookieName:"gatekeeper_device",
		DeviceLifetime:time.Hour,
		MaxAttempts:3,
		IdentityHasher:identity.NewHasher("test-key"),
		Store:st,
		RateLimiter:ratelimit.NewMemory(),
		SiteRateLimit:10,
		SiteRateWindow:10*time.Minute,
		IdentityRateLimit:2,
		IdentityRateWindow:10*time.Minute,
	})

	submit:=func()int{
		form:=url.Values{"email":{"person@a.test"},"return":{"/protected"}}
		req:=httptest.NewRequest("POST","http://a.test/login",strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type","application/x-www-form-urlencoded")
		res:=httptest.NewRecorder()
		s.startChallenge(res,req)
		return res.Code
	}
	if got:=submit();got!=302{t.Fatalf("first status=%d, want 302",got)}
	if got:=submit();got!=302{t.Fatalf("second status=%d, want 302",got)}
	if got:=submit();got!=429{t.Fatalf("third status=%d, want 429",got)}
}

func TestSiteRateLimitBlocksEleventhOTPRequest(t *testing.T){
	st:=store.NewMemory()
	sites:=site.NewMemory()
	if err:=sites.Put(context.Background(),site.Site{ID:"a",Hosts:[]string{"a.test"},AccessRules:[]access.Rule{{Type:access.RuleDomain,Value:"a.test"}}});err!=nil{t.Fatal(err)}
	s:=New(Config{
		Sites:sites,
		CookieName:"gatekeeper_device",
		DeviceLifetime:time.Hour,
		MaxAttempts:3,
		IdentityHasher:identity.NewHasher("test-key"),
		Store:st,
		RateLimiter:ratelimit.NewMemory(),
		SiteRateLimit:10,
		SiteRateWindow:10*time.Minute,
		IdentityRateLimit:2,
		IdentityRateWindow:10*time.Minute,
	})

	for i:=0;i<10;i++{
		form:=url.Values{"email":{fmt.Sprintf("person%d@a.test",i)},"return":{"/protected"}}
		req:=httptest.NewRequest("POST","http://a.test/login",strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type","application/x-www-form-urlencoded")
		res:=httptest.NewRecorder()
		s.startChallenge(res,req)
		if res.Code!=302{t.Fatalf("request %d status=%d, want 302",i+1,res.Code)}
	}

	form:=url.Values{"email":{"person10@a.test"},"return":{"/protected"}}
	req:=httptest.NewRequest("POST","http://a.test/login",strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type","application/x-www-form-urlencoded")
	res:=httptest.NewRecorder()
	s.startChallenge(res,req)
	if res.Code!=429{t.Fatalf("eleventh status=%d, want 429",res.Code)}
	if res.Header().Get("Retry-After")==""{t.Fatal("rate-limited response missing Retry-After")}
}


func TestStateTimeoutFailsClosed(t *testing.T){
	st:=store.NewMemory()
	sites:=site.NewMemory()
	if err:=sites.Put(context.Background(),site.Site{ID:"a",Hosts:[]string{"a.test"},AccessRules:[]access.Rule{{Type:access.RuleDomain,Value:"a.test"}}});err!=nil{t.Fatal(err)}
	s:=New(Config{
		Sites:sites,
		CookieName:"gatekeeper_device",
		DeviceLifetime:time.Hour,
		MaxAttempts:3,
		IdentityHasher:identity.NewHasher("test-key"),
		Store:st,
		RateLimiter:blockingLimiter{},
		StateTimeout:20*time.Millisecond,
	})

	form:=url.Values{"email":{"person@a.test"},"return":{"/protected"}}
	req:=httptest.NewRequest("POST","http://a.test/login",strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type","application/x-www-form-urlencoded")
	res:=httptest.NewRecorder()

	started:=time.Now()
	s.Handler().ServeHTTP(res,req)
	elapsed:=time.Since(started)

	if res.Code!=503{t.Fatalf("status=%d, want 503",res.Code)}
	if elapsed>250*time.Millisecond{t.Fatalf("state timeout took %s, want under 250ms",elapsed)}
}
