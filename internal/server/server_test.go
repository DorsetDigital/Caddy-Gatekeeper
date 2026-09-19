package server

import (
	"context"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/identity"
	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/store"
)

func testServer() (*Server,*store.Memory) {
	st:=store.NewMemory()
	return New(Config{AllowedEmail:"developer@example.test",CookieName:"gatekeeper_device",DeviceLifetime:30*24*time.Hour,MaxAttempts:3,IdentityHasher:identity.NewHasher("test-key"),Store:st}),st
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
