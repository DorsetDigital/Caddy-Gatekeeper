package site

import (
	"context"
	"errors"
	"testing"

	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/access"
)

func TestValidateAndNormaliseSite(t *testing.T) {
	got,err:=ValidateAndNormalise(Site{
		ID:" test ",
		Hosts:[]string{" Example.COM "},
		AccessRules:[]access.Rule{
			{Type:access.RuleEmail,Value:" Admin@Example.com "},
			{Type:access.RuleDomain,Value:" Example.com "},
		},
	})
	if err!=nil{t.Fatal(err)}
	if got.ID!="test"{t.Fatalf("ID=%q",got.ID)}
	if len(got.Hosts)!=1||got.Hosts[0]!="example.com"{t.Fatalf("Hosts=%v",got.Hosts)}
	if got.AccessRules[0].Value!="admin@example.com"{t.Fatalf("email rule=%q",got.AccessRules[0].Value)}
	if got.AccessRules[1].Value!="example.com"{t.Fatalf("domain rule=%q",got.AccessRules[1].Value)}
}

func TestValidateRejectsUnsupportedRuleType(t *testing.T) {
	_,err:=ValidateAndNormalise(Site{
		ID:"test",
		Hosts:[]string{"example.com"},
		AccessRules:[]access.Rule{{Type:"wildcard",Value:"example.com"}},
	})
	if err==nil{t.Fatal("unsupported rule type accepted")}
}

func TestValidateRejectsDuplicateHosts(t *testing.T) {
	_,err:=ValidateAndNormalise(Site{
		ID:"test",
		Hosts:[]string{"example.com","EXAMPLE.COM"},
	})
	if err==nil{t.Fatal("duplicate normalised host accepted")}
}

func TestMemoryRepositoryPreventsHostReassignment(t *testing.T) {
	repo:=NewMemory()
	ctx:=context.Background()
	if err:=repo.Put(ctx,Site{ID:"a",Hosts:[]string{"example.com"}});err!=nil{t.Fatal(err)}
	err:=repo.Put(ctx,Site{ID:"b",Hosts:[]string{"example.com"}})
	if !errors.Is(err,ErrHostConflict){t.Fatalf("error=%v, want ErrHostConflict",err)}

	got,err:=repo.GetByHost(ctx,"example.com")
	if err!=nil{t.Fatal(err)}
	if got.ID!="a"{t.Fatalf("host owner=%q, want a",got.ID)}
}

func TestMemoryRepositoryReleasesRemovedHost(t *testing.T) {
	repo:=NewMemory()
	ctx:=context.Background()
	if err:=repo.Put(ctx,Site{ID:"a",Hosts:[]string{"old.example.com","new.example.com"}});err!=nil{t.Fatal(err)}
	if err:=repo.Put(ctx,Site{ID:"a",Hosts:[]string{"new.example.com"}});err!=nil{t.Fatal(err)}
	if err:=repo.Put(ctx,Site{ID:"b",Hosts:[]string{"old.example.com"}});err!=nil{t.Fatalf("released host could not be reassigned: %v",err)}
}
