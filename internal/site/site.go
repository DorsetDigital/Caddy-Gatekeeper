package site

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"

	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/access"
)

var (
	ErrNotFound = errors.New("gatekeeper site not found")
	ErrHostConflict = errors.New("gatekeeper host already assigned")
)

type Site struct {
	ID string `json:"id"`
	Hosts []string `json:"hosts"`
	AccessRules []access.Rule `json:"access_rules"`
}

type Repository interface {
	Put(context.Context, Site) error
	Get(context.Context, string) (Site, error)
	GetByHost(context.Context, string) (Site, error)
	List(context.Context) ([]Site, error)
	Delete(context.Context, string) error
}

func ValidateAndNormalise(s Site) (Site, error) {
	s.ID = strings.TrimSpace(s.ID)
	if s.ID == "" {
		return Site{}, errors.New("site id is required")
	}

	if len(s.Hosts) == 0 {
		return Site{}, errors.New("at least one host is required")
	}

	seenHosts := make(map[string]struct{}, len(s.Hosts))
	hosts := make([]string, 0, len(s.Hosts))
	for _, raw := range s.Hosts {
		host := normaliseHost(raw)
		if host == "" || strings.ContainsAny(host, " /\\") {
			return Site{}, fmt.Errorf("invalid host %q", raw)
		}
		if _, exists := seenHosts[host]; exists {
			return Site{}, fmt.Errorf("duplicate host %q", host)
		}
		seenHosts[host] = struct{}{}
		hosts = append(hosts, host)
	}
	s.Hosts = hosts

	rules := make([]access.Rule, 0, len(s.AccessRules))
	for _, rule := range s.AccessRules {
		value := strings.ToLower(strings.TrimSpace(rule.Value))
		if value == "" {
			return Site{}, errors.New("access rule value is required")
		}

		switch rule.Type {
		case access.RuleEmail:
			address, err := mail.ParseAddress(value)
			if err != nil || strings.ToLower(address.Address) != value {
				return Site{}, fmt.Errorf("invalid email access rule %q", rule.Value)
			}
		case access.RuleDomain:
			if strings.Contains(value, "@") || strings.ContainsAny(value, " /\\:") || !strings.Contains(value, ".") {
				return Site{}, fmt.Errorf("invalid domain access rule %q", rule.Value)
			}
		default:
			return Site{}, fmt.Errorf("unsupported access rule type %q", rule.Type)
		}

		rules = append(rules, access.Rule{Type: rule.Type, Value: value})
	}
	s.AccessRules = rules

	return s, nil
}
