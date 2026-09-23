package management

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/site"
)

type failingRepository struct{}

func (failingRepository) Put(context.Context,site.Site)error{return errors.New("unavailable")}
func (failingRepository) Get(context.Context,string)(site.Site,error){return site.Site{},errors.New("unavailable")}
func (failingRepository) GetByHost(context.Context,string)(site.Site,error){return site.Site{},errors.New("unavailable")}
func (failingRepository) List(context.Context)([]site.Site,error){return nil,errors.New("unavailable")}
func (failingRepository) Delete(context.Context,string)error{return errors.New("unavailable")}

func TestReadyReportsRepositoryHealth(t *testing.T) {
	okServer:=New(site.NewMemory(),"token")
	okReq:=httptest.NewRequest(http.MethodGet,"/ready",nil)
	okRes:=httptest.NewRecorder()
	okServer.Handler().ServeHTTP(okRes,okReq)
	if okRes.Code!=http.StatusNoContent{t.Fatalf("healthy status=%d",okRes.Code)}

	badServer:=New(failingRepository{},"token")
	badReq:=httptest.NewRequest(http.MethodGet,"/ready",nil)
	badRes:=httptest.NewRecorder()
	badServer.Handler().ServeHTTP(badRes,badReq)
	if badRes.Code!=http.StatusServiceUnavailable{t.Fatalf("unhealthy status=%d",badRes.Code)}
}

func TestPutRejectsUnsupportedRuleType(t *testing.T) {
	s:=New(site.NewMemory(),"token")
	req:=httptest.NewRequest(http.MethodPut,"/api/v1/sites/a",bytes.NewBufferString(`{"hosts":["example.com"],"access_rules":[{"type":"wildcard","value":"example.com"}]}`))
	req.Header.Set("Authorization","Bearer token")
	req.Header.Set("Content-Type","application/json")
	res:=httptest.NewRecorder()
	s.Handler().ServeHTTP(res,req)
	if res.Code!=http.StatusBadRequest{t.Fatalf("status=%d, want 400",res.Code)}
}

func TestPutRejectsHostOwnedByAnotherSite(t *testing.T) {
	s:=New(site.NewMemory(),"token")
	put:=func(id string)int{
		req:=httptest.NewRequest(http.MethodPut,"/api/v1/sites/"+id,bytes.NewBufferString(`{"hosts":["example.com"],"access_rules":[{"type":"domain","value":"example.com"}]}`))
		req.Header.Set("Authorization","Bearer token")
		req.Header.Set("Content-Type","application/json")
		res:=httptest.NewRecorder()
		s.Handler().ServeHTTP(res,req)
		return res.Code
	}
	if got:=put("a");got!=http.StatusOK{t.Fatalf("first PUT status=%d",got)}
	if got:=put("b");got!=http.StatusConflict{t.Fatalf("second PUT status=%d, want 409",got)}
}


func TestPutRejectsTrailingJSON(t *testing.T) {
	s:=New(site.NewMemory(),"token")
	req:=httptest.NewRequest(http.MethodPut,"/api/v1/sites/a",bytes.NewBufferString(
		`{"hosts":["example.com"],"access_rules":[]}`+"\n"+`{"hosts":["second.example.com"]}`,
	))
	req.Header.Set("Authorization","Bearer token")
	req.Header.Set("Content-Type","application/json")
	res:=httptest.NewRecorder()
	s.Handler().ServeHTTP(res,req)
	if res.Code!=http.StatusBadRequest{t.Fatalf("status=%d, want 400",res.Code)}
}
