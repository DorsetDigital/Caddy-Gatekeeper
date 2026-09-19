package store

import (
	"context"
	"errors"
	"time"
)

var ErrNotFound = errors.New("gatekeeper state not found")

type Challenge struct {
	IdentityID string
	CodeHash []byte
	ReturnURL string
	Attempts int
}

type Device struct {
	IdentityID string
	LastSeen time.Time
}

type Store interface {
	CreateChallenge(context.Context, string, Challenge, time.Duration) error
	GetChallenge(context.Context, string) (Challenge, error)
	RecordFailedAttempt(context.Context, string, int) (remaining int, exhausted bool, err error)
	ConsumeChallenge(context.Context, string) error
	CreateDevice(context.Context, string, Device, time.Duration) error
	GetDevice(context.Context, string) (Device, error)
	RefreshDevice(context.Context, string, Device, time.Duration) error
	DeleteDevice(context.Context, string) error
}
