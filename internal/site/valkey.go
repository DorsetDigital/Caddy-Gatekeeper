package site

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/redis/go-redis/v9"
)

type Valkey struct { client redis.UniversalClient; prefix string }

func NewValkey(client redis.UniversalClient,prefix string)*Valkey{return &Valkey{client:client,prefix:prefix}}
func(v *Valkey)siteKey(id string)string{return v.prefix+"config:site:"+id}
func(v *Valkey)hostKey(host string)string{return v.prefix+"config:host:"+normaliseHost(host)}
func(v *Valkey)indexKey()string{return v.prefix+"config:sites"}

func(v *Valkey)Put(ctx context.Context,s Site)error{
	s.ID=strings.TrimSpace(s.ID);if s.ID==""{return errors.New("site id is required")}
	old,_:=v.Get(ctx,s.ID)
	for i:=range s.Hosts{s.Hosts[i]=normaliseHost(s.Hosts[i])}
	data,err:=json.Marshal(s);if err!=nil{return err}
	pipe:=v.client.TxPipeline()
	pipe.Set(ctx,v.siteKey(s.ID),data,0);pipe.SAdd(ctx,v.indexKey(),s.ID)
	for _,h:=range old.Hosts{pipe.Del(ctx,v.hostKey(h))}
	for _,h:=range s.Hosts{if h!=""{pipe.Set(ctx,v.hostKey(h),s.ID,0)}}
	_,err=pipe.Exec(ctx);return err
}
func(v *Valkey)Get(ctx context.Context,id string)(Site,error){
	raw,err:=v.client.Get(ctx,v.siteKey(id)).Bytes();if errors.Is(err,redis.Nil){return Site{},ErrNotFound};if err!=nil{return Site{},err}
	var s Site;if err:=json.Unmarshal(raw,&s);err!=nil{return Site{},err};return s,nil
}
func(v *Valkey)GetByHost(ctx context.Context,host string)(Site,error){
	id,err:=v.client.Get(ctx,v.hostKey(host)).Result();if errors.Is(err,redis.Nil){return Site{},ErrNotFound};if err!=nil{return Site{},err};return v.Get(ctx,id)
}
func(v *Valkey)List(ctx context.Context)([]Site,error){
	ids,err:=v.client.SMembers(ctx,v.indexKey()).Result();if err!=nil{return nil,err};sort.Strings(ids)
	out:=make([]Site,0,len(ids));for _,id:=range ids{s,err:=v.Get(ctx,id);if errors.Is(err,ErrNotFound){continue};if err!=nil{return nil,err};out=append(out,s)}
	return out,nil
}
func(v *Valkey)Delete(ctx context.Context,id string)error{
	s,err:=v.Get(ctx,id);if errors.Is(err,ErrNotFound){return nil};if err!=nil{return err}
	pipe:=v.client.TxPipeline();pipe.Del(ctx,v.siteKey(id));pipe.SRem(ctx,v.indexKey(),id);for _,h:=range s.Hosts{pipe.Del(ctx,v.hostKey(h))};_,err=pipe.Exec(ctx);return err
}
func normaliseHost(h string)string{h=strings.ToLower(strings.TrimSpace(h));if i:=strings.IndexByte(h,':');i>=0{h=h[:i]};return h}
