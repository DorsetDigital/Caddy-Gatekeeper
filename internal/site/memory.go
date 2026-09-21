package site

import (
	"context"
	"strings"
	"sync"
)

type Memory struct{mu sync.RWMutex;sites map[string]Site;hosts map[string]string}
func NewMemory()*Memory{return &Memory{sites:map[string]Site{},hosts:map[string]string{}}}
func(m *Memory)Put(_ context.Context,s Site)error{m.mu.Lock();defer m.mu.Unlock();if old,ok:=m.sites[s.ID];ok{for _,h:=range old.Hosts{delete(m.hosts,normaliseHost(h))}};for _,h:=range s.Hosts{m.hosts[normaliseHost(h)]=s.ID};m.sites[s.ID]=s;return nil}
func(m *Memory)Get(_ context.Context,id string)(Site,error{ m.mu.RLock();defer m.mu.RUnlock();s,ok:=m.sites[id];if !ok{return Site{},ErrNotFound};return s,nil}
