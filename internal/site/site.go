package site

import (
	"context"
	"errors"

	"github.com/DorsetDigital/Caddy-Gatekeeper/internal/access"
)

var ErrNotFound = errors.New("gatekeeper site not found")

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
