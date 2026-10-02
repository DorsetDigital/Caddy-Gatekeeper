package site

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/redis/go-redis/v9"
)

type Valkey struct { client redis.UniversalClient; prefix string }

func NewValkey(client redis.UniversalClient,prefix string)*Valkey{return &Valkey{client:client,prefix:prefix}}
func(v *Valkey)siteKey(id string)string{return v.prefix+"config:site:"+id}
func(v *Valkey)hostKey(host string)string{return v.prefix+"config:host:"+normaliseHost(host)}
func(v *Valkey)indexKey()string{return v.prefix+"config:sites"}

var releaseHostScript=redis.NewScript(`
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
`)

func(v *Valkey)Put(ctx context.Context,s Site)error{
	var err error
	s,err=ValidateAndNormalise(s);if err!=nil{return err}

	old,err:=v.Get(ctx,s.ID)
	if errors.Is(err,ErrNotFound){old=Site{}}else if err!=nil{return err}
	acquired:=make([]string,0,len(s.Hosts))
	rollback:=func(){
		for _,h:=range acquired{
			_,_=releaseHostScript.Run(context.Background(),v.client,[]string{v.hostKey(h)},s.ID).Result()
		}
	}

	for _,h:=range s.Hosts{
		key:=v.hostKey(h)
		claimed,err:=v.client.SetNX(ctx,key,s.ID,0).Result()
		if err!=nil{rollback();return err}
		if claimed{acquired=append(acquired,h);continue}

		owner,err:=v.client.Get(ctx,key).Result()
		if err!=nil{rollback();return err}
		if owner!=s.ID{rollback();return fmt.Errorf("%w: %s",ErrHostConflict,h)}
	}

	data,err:=json.Marshal(s);if err!=nil{rollback();return err}
	pipe:=v.client.TxPipeline()
	pipe.Set(ctx,v.siteKey(s.ID),data,0)
	pipe.SAdd(ctx,v.indexKey(),s.ID)
	if _,err=pipe.Exec(ctx);err!=nil{rollback();return err}

	current:=make(map[string]struct{},len(s.Hosts))
	for _,h:=range s.Hosts{current[h]=struct{}{}}
	for _,h:=range old.Hosts{
		h=normaliseHost(h)
		if _,keep:=current[h];keep{continue}
		if _,err:=releaseHostScript.Run(ctx,v.client,[]string{v.hostKey(h)},s.ID).Result();err!=nil{return err}
	}
	return nil
}

func(v *Valkey)Get(ctx context.Context,id string)(Site,error){
	raw,err:=v.client.Get(ctx,v.siteKey(id)).Bytes();if errors.Is(err,redis.Nil){return Site{},ErrNotFound};if err!=nil{return Site{},err}
	var s Site;if err:=json.Unmarshal(raw,&s);err!=nil{return Site{},err};return s,nil
}

func(v *Valkey)GetByHost(ctx context.Context,host string)(Site,error){
	host=normaliseHost(host)
	id,err:=v.client.Get(ctx,v.hostKey(host)).Result();if errors.Is(err,redis.Nil){return Site{},ErrNotFound};if err!=nil{return Site{},err}
	s,err:=v.Get(ctx,id);if err!=nil{return Site{},err}
	for _,configured:=range s.Hosts{if normaliseHost(configured)==host{return s,nil}}
	return Site{},ErrNotFound
}

func(v *Valkey)List(ctx context.Context)([]Site,error){
	ids,err:=v.client.SMembers(ctx,v.indexKey()).Result();if err!=nil{return nil,err};sort.Strings(ids)
	out:=make([]Site,0,len(ids));for _,id:=range ids{s,err:=v.Get(ctx,id);if errors.Is(err,ErrNotFound){continue};if err!=nil{return nil,err};out=append(out,s)}
	return out,nil
}

func(v *Valkey)Delete(ctx context.Context,id string)error{
	s,err:=v.Get(ctx,id);if errors.Is(err,ErrNotFound){return nil};if err!=nil{return err}
	pipe:=v.client.TxPipeline();pipe.Del(ctx,v.siteKey(id));pipe.SRem(ctx,v.indexKey(),id);if _,err=pipe.Exec(ctx);err!=nil{return err}
	for _,h:=range s.Hosts{
		if _,err:=releaseHostScript.Run(ctx,v.client,[]string{v.hostKey(h)},id).Result();err!=nil{return err}
	}
	return nil
}

func normaliseHost(h string)string{
	h=strings.ToLower(strings.TrimSpace(h))
	h=strings.TrimSuffix(h,".")
	if i:=strings.IndexByte(h,':');i>=0{h=h[:i]}
	return h
}
