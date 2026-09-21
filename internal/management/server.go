package management

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/site"
)

type Server struct{sites site.Repository;token string}
func New(sites site.Repository,token string)*Server{return &Server{sites:sites,token:token}}
func(s *Server)Handler()http.Handler{
	mux:=http.NewServeMux()
	mux.HandleFunc("GET /health",func(w http.ResponseWriter,_ *http.Request){w.WriteHeader(http.StatusNoContent)})
	mux.HandleFunc("GET /api/v1/sites",s.list)
	mux.HandleFunc("GET /api/v1/sites/{id}",s.get)
	mux.HandleFunc("PUT /api/v1/sites/{id}",s.put)
	mux.HandleFunc("DELETE /api/v1/sites/{id}",s.delete)
	return s.auth(mux)
}
func(s *Server)auth(next http.Handler)http.Handler{return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
	if r.URL.Path=="/health"{next.ServeHTTP(w,r);return}
	got:=strings.TrimPrefix(r.Header.Get("Authorization"),"Bearer ")
	if s.token==""||subtle.ConstantTimeCompare([]byte(got),[]byte(s.token))!=1{http.Error(w,"Unauthorized",http.StatusUnauthorized);return}
	next.ServeHTTP(w,r)
})}
func(s *Server)list(w http.ResponseWriter,r *http.Request){sites,err:=s.sites.List(r.Context());if err!=nil{http.Error(w,"Configuration store unavailable",503);return};writeJSON(w,sites)}
func(s *Server)get(w http.ResponseWriter,r *http.Request){v,err:=s.sites.Get(r.Context(),r.PathValue("id"));if errors.Is(err,site.ErrNotFound){http.NotFound(w,r);return};if err!=nil{http.Error(w,"Configuration store unavailable",503);return};writeJSON(w,v)}
func(s *Server)put(w http.ResponseWriter,r *http.Request){
	r.Body=http.MaxBytesReader(w,r.Body,64<<10);var v site.Site
	if err:=json.NewDecoder(r.Body).Decode(&v);err!=nil{http.Error(w,"Invalid JSON",400);return}
	v.ID=r.PathValue("id");if len(v.Hosts)==0{http.Error(w,"At least one host is required",400);return}
	if err:=s.sites.Put(r.Context(),v);err!=nil{http.Error(w,"Configuration store unavailable",503);return};writeJSON(w,v)
}
func(s *Server)delete(w http.ResponseWriter,r *http.Request){if err:=s.sites.Delete(r.Context(),r.PathValue("id"));err!=nil{http.Error(w,"Configuration store unavailable",503);return};w.WriteHeader(http.StatusNoContent)}
func writeJSON(w http.ResponseWriter,v any){w.Header().Set("Content-Type","application/json");_ = json.NewEncoder(w).Encode(v)}
