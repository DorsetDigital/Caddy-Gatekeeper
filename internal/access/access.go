package access

import (
	"net/mail"
	"strings"
)

type RuleType string

const (
	RuleEmail RuleType = "email"
	RuleDomain RuleType = "domain"
)

type Rule struct {
	Type RuleType `json:"type"`
	Value string `json:"value"`
}

type Matcher struct { rules []Rule }

func NewMatcher(rules []Rule) Matcher {
	normalised:=make([]Rule,0,len(rules))
	for _,rule:=range rules {
		value:=strings.ToLower(strings.TrimSpace(rule.Value))
		if value!="" { normalised=append(normalised,Rule{Type:rule.Type,Value:value}) }
	}
	return Matcher{rules:normalised}
}

func (m Matcher) Allowed(identity string) bool {
	address,err:=mail.ParseAddress(strings.TrimSpace(identity))
	if err!=nil{return false}
	email:=strings.ToLower(address.Address)
	at:=strings.LastIndex(email,"@")
	if at<=0||at==len(email)-1{return false}
	domain:=email[at+1:]
	for _,rule:=range m.rules {
		switch rule.Type {
		case RuleEmail:
			if email==rule.Value{return true}
		case RuleDomain:
			if domain==rule.Value{return true}
		}
	}
	return false
}
