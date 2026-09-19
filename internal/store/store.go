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

type VerifyStatus int
const (
	VerifyNotFound VerifyStatus = iota
	VerifyInvalid
	VerifyExhausted
	VerifySuccess
)
type VerifyResult struct {
	Status VerifyStatus
	Challenge Challenge
	Remaining int
}

type Device struct {
	IdentityID string
	LastSeen time.Time
}

type Store interface {
	CreateChallenge(context.Context, string, Challenge, time.Duration) error
	GetChallenge(context.Context, string) (Challenge, error)
	VerifyChallenge(context.Context, string, []byte, int) (VerifyResult, error)
	CreateDevice(context.Context, string, Device, time.Duration) error
	GetDevice(context.Context, string) (Device, error)
	RefreshDevice(context.Context, string, Device, time.Duration) error
	DeleteDevice(context.Context, string) error
	Close() error
}
