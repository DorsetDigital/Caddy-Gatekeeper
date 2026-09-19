package store

import (
	"context"
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

func NewMemory() *Memory {
	return &Memory{challenges: map[string]expiringChallenge{}, devices: map[string]expiringDevice{}}
}

func (m *Memory) CreateChallenge(_ context.Context, id string, ch Challenge, ttl time.Duration) error {
	m.mu.Lock(); defer m.mu.Unlock()
	m.challenges[id] = expiringChallenge{Challenge: ch, ExpiresAt: time.Now().Add(ttl)}
	return nil
}
func (m *Memory) GetChallenge(_ context.Context, id string) (Challenge, error) {
	m.mu.Lock(); defer m.mu.Unlock()
	ch, ok := m.challenges[id]
	if !ok || time.Now().After(ch.ExpiresAt) { delete(m.challenges,id); return Challenge{}, ErrNotFound }
	return ch.Challenge,nil
}
func (m *Memory) RecordFailedAttempt(_ context.Context, id string, max int) (int,bool,error) {
	m.mu.Lock(); defer m.mu.Unlock()
	ch,ok:=m.challenges[id]
	if !ok || time.Now().After(ch.ExpiresAt) { delete(m.challenges,id); return 0,true,ErrNotFound }
	ch.Attempts++
	if ch.Attempts >= max { delete(m.challenges,id); return 0,true,nil }
	m.challenges[id]=ch
	return max-ch.Attempts,false,nil
}
func (m *Memory) ConsumeChallenge(_ context.Context,id string) error { m.mu.Lock(); defer m.mu.Unlock(); delete(m.challenges,id); return nil }
func (m *Memory) CreateDevice(_ context.Context,id string,d Device,ttl time.Duration) error { m.mu.Lock(); defer m.mu.Unlock(); m.devices[id]=expiringDevice{Device:d,ExpiresAt:time.Now().Add(ttl)}; return nil }
func (m *Memory) GetDevice(_ context.Context,id string)(Device,error){ m.mu.Lock(); defer m.mu.Unlock(); d,ok:=m.devices[id]; if !ok || time.Now().After(d.ExpiresAt){delete(m.devices,id);return Device{},ErrNotFound}; return d.Device,nil }
func (m *Memory) RefreshDevice(_ context.Context,id string,d Device,ttl time.Duration)error{m.mu.Lock();defer m.mu.Unlock(); if _,ok:=m.devices[id];!ok{return ErrNotFound};m.devices[id]=expiringDevice{Device:d,ExpiresAt:time.Now().Add(ttl)};return nil}
func (m *Memory) DeleteDevice(_ context.Context,id string)error{m.mu.Lock();defer m.mu.Unlock();delete(m.devices,id);return nil}
