package site

import (
	"context"
	"sort"
	"sync"
)

type Memory struct{mu sync.RWMutex;sites map[string]Site;hosts map[string]string}
func NewMemory()*Memory{return &Memory{sites:map[string]Site{},hosts:map[string]string{}}}
func(m *Memory)Put(_ context.Context,s Site)error{m.mu.Lock();defer m.mu.Unlock();if old,ok:=m.sites[s.ID];ok{for _,h:=range old.Hosts{delete(m.hosts,normaliseHost(h))}};for _,h:=range s.Hosts{m.hosts[normaliseHost(h)]=s.ID};m.sites[s.ID]=s;return nil}
func(m *Memory)Get(_ context.Context,id string)(Site,error){m.mu.RLock();defer m.mu.RUnlock();s,ok:=m.sites[id];if !ok{return Site{},ErrNotFound};return s,nil}
func(m *Memory)GetByHost(ctx context.Context,h string)(Site,error){m.mu.RLock();id,ok:=m.hosts[normaliseHost(h)];m.mu.RUnlock();if !ok{return Site{},ErrNotFound};return m.Get(ctx,id)}
func(m *Memory)List(_ context.Context)([]Site,error){m.mu.RLock();defer m.mu.RUnlock();ids:=make([]string,0,len(m.sites));for id:=range m.sites{ids=append(ids,id)};sort.Strings(ids);out:=make([]Site,0,len(ids));for _,id:=range ids{out=append(out,m.sites[id])};return out,nil}
func(m *Memory)Delete(_ context.Context,id string)error{m.mu.Lock();defer m.mu.Unlock();if s,ok:=m.sites[id];ok{for _,h:=range s.Hosts{delete(m.hosts,normaliseHost(h))};delete(m.sites,id)};return nil}
