package store

import (
	"context"
	"crypto/subtle"
	"sync"
	"time"
)

type expiringChallenge struct { Challenge; ExpiresAt time.Time }
type expiringDevice struct { Device; ExpiresAt time.Time }

type Memory struct {
	mu sync.Mutex
	challenges map[string]expiringChallenge
	devices map[string]expiringDevice
}
func NewMemory()*Memory{return &Memory{challenges:map[string]expiringChallenge{},devices:map[string]expiringDevice{}}}
func(m *Memory)CreateChallenge(_ context.Context,id string,ch Challenge,ttl time.Duration)error{m.mu.Lock();defer m.mu.Unlock();m.challenges[id]=expiringChallenge{Challenge:ch,ExpiresAt:time.Now().Add(ttl)};return nil}
func(m *Memory)GetChallenge(_ context.Context,id string)(Challenge,error){m.mu.Lock();defer m.mu.Unlock();ch,ok:=m.challenges[id];if !ok||time.Now().After(ch.ExpiresAt){delete(m.challenges,id);return Challenge{},ErrNotFound};return ch.Challenge,nil}
func(m *Memory)VerifyChallenge(_ context.Context,id string,submitted []byte,max int)(VerifyResult,error){
	m.mu.Lock();defer m.mu.Unlock()
	ch,ok:=m.challenges[id];if !ok||time.Now().After(ch.ExpiresAt){delete(m.challenges,id);return VerifyResult{Status:VerifyNotFound},nil}
	if subtle.ConstantTimeCompare(submitted,ch.CodeHash)==1{delete(m.challenges,id);return VerifyResult{Status:VerifySuccess,Challenge:ch.Challenge},nil}
	ch.Attempts++
	if ch.Attempts>=max{delete(m.challenges,id);return VerifyResult{Status:VerifyExhausted,Challenge:ch.Challenge},nil}
	m.challenges[id]=ch;return VerifyResult{Status:VerifyInvalid,Challenge:ch.Challenge,Remaining:max-ch.Attempts},nil
}
func(m *Memory)CreateDevice(_ context.Context,id string,d Device,ttl time.Duration)error{m.mu.Lock();defer m.mu.Unlock();m.devices[id]=expiringDevice{Device:d,ExpiresAt:time.Now().Add(ttl)};return nil}
func(m *Memory)GetDevice(_ context.Context,id string)(Device,error){m.mu.Lock();defer m.mu.Unlock();d,ok:=m.devices[id];if !ok||time.Now().After(d.ExpiresAt){delete(m.devices,id);return Device{},ErrNotFound};return d.Device,nil}
func(m *Memory)RefreshDevice(_ context.Context,id string,d Device,ttl time.Duration)error{m.mu.Lock();defer m.mu.Unlock();if _,ok:=m.devices[id];!ok{return ErrNotFound};m.devices[id]=expiringDevice{Device:d,ExpiresAt:time.Now().Add(ttl)};return nil}
func(m *Memory)DeleteDevice(_ context.Context,id string)error{m.mu.Lock();defer m.mu.Unlock();delete(m.devices,id);return nil}
func(m *Memory)Close()error{return nil}
