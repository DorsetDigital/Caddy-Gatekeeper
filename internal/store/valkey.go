package store

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

type ValkeyConfig struct {
	Mode string
	Addrs []string
	Username string
	Password string
	TLS bool
	Prefix string
}

type Valkey struct {
	client redis.UniversalClient
	prefix string
}

func NewValkey(ctx context.Context,cfg ValkeyConfig)(*Valkey,error){
	if len(cfg.Addrs)==0{return nil,errors.New("at least one Valkey address is required")}
	var tlsConfig *tls.Config
	if cfg.TLS { tlsConfig=&tls.Config{MinVersion:tls.VersionTLS12} }
	opts:=&redis.UniversalOptions{Addrs:cfg.Addrs,Username:cfg.Username,Password:cfg.Password,TLSConfig:tlsConfig}
	if strings.EqualFold(cfg.Mode,"cluster"){opts.DB=0}
	client:=redis.NewUniversalClient(opts)
	if err:=client.Ping(ctx).Err();err!=nil{_ = client.Close();return nil,fmt.Errorf("connect to Valkey: %w",err)}
	prefix:=cfg.Prefix;if prefix==""{prefix="gatekeeper:"}
	return &Valkey{client:client,prefix:prefix},nil
}
func(v *Valkey)challengeKey(id string)string{return v.prefix+"challenge:"+id}
func(v *Valkey)deviceKey(id string)string{return v.prefix+"device:"+id}

func(v *Valkey)CreateChallenge(ctx context.Context,id string,ch Challenge,ttl time.Duration)error{
	key:=v.challengeKey(id)
	pipe:=v.client.TxPipeline()
	pipe.HSet(ctx,key,map[string]any{"site":ch.SiteID,"identity":ch.IdentityID,"code":base64.RawStdEncoding.EncodeToString(ch.CodeHash),"return":ch.ReturnURL,"attempts":ch.Attempts})
	pipe.Expire(ctx,key,ttl)
	_,err:=pipe.Exec(ctx);return err
}

func(v *Valkey)GetChallenge(ctx context.Context,id string)(Challenge,error){
	values,err:=v.client.HGetAll(ctx,v.challengeKey(id)).Result();if err!=nil{return Challenge{},err};if len(values)==0{return Challenge{},ErrNotFound};return decodeChallenge(values)
}

var verifyScript=redis.NewScript(`
local values = redis.call('HMGET', KEYS[1], 'site', 'identity', 'code', 'return', 'attempts')
if not values[1] then return {'notfound'} end
if values[3] == ARGV[1] then
  redis.call('DEL', KEYS[1])
  return {'success', values[1], values[2], values[4]}
end
local attempts = tonumber(values[5] or '0') + 1
local max = tonumber(ARGV[2])
if attempts >= max then
  redis.call('DEL', KEYS[1])
  return {'exhausted', values[1], values[2], values[4]}
end
redis.call('HSET', KEYS[1], 'attempts', attempts)
return {'invalid', tostring(max-attempts), values[1], values[2], values[4]}
`)

func(v *Valkey)VerifyChallenge(ctx context.Context,id string,submitted []byte,max int)(VerifyResult,error){
	raw,err:=verifyScript.Run(ctx,v.client,[]string{v.challengeKey(id)},base64.RawStdEncoding.EncodeToString(submitted),max).Result();if err!=nil{return VerifyResult{},err}
	items,ok:=raw.([]interface{});if !ok||len(items)==0{return VerifyResult{},errors.New("invalid Valkey verification response")}
	status,_:=items[0].(string)
	switch status{
	case "notfound":return VerifyResult{Status:VerifyNotFound},nil
	case "success","exhausted":
		if len(items)<5{return VerifyResult{},errors.New("incomplete Valkey verification response")}
		ch:=Challenge{SiteID:fmt.Sprint(items[1]),IdentityID:fmt.Sprint(items[2]),ReturnURL:fmt.Sprint(items[3])}
		if status=="success"{return VerifyResult{Status:VerifySuccess,Challenge:ch},nil}
		return VerifyResult{Status:VerifyExhausted,Challenge:ch},nil
	case "invalid":
		if len(items)<4{return VerifyResult{},errors.New("incomplete Valkey verification response")}
		remaining,err:=strconv.Atoi(fmt.Sprint(items[1]));if err!=nil{return VerifyResult{},err}
		return VerifyResult{Status:VerifyInvalid,Remaining:remaining,Challenge:Challenge{SiteID:fmt.Sprint(items[2]),IdentityID:fmt.Sprint(items[3]),ReturnURL:fmt.Sprint(items[4])}},nil
	default:return VerifyResult{},errors.New("unknown Valkey verification response")
	}
}

func(v *Valkey)CreateDevice(ctx context.Context,id string,d Device,ttl time.Duration)error{
	key:=v.deviceKey(id)
	pipe:=v.client.TxPipeline()
	pipe.HSet(ctx,key,map[string]any{"site":d.SiteID,"identity":d.IdentityID,"last_seen":d.LastSeen.Unix()})
	pipe.Expire(ctx,key,ttl)
	_,err:=pipe.Exec(ctx);return err
}
func(v *Valkey)GetDevice(ctx context.Context,id string)(Device,error){
	values,err:=v.client.HGetAll(ctx,v.deviceKey(id)).Result();if err!=nil{return Device{},err};if len(values)==0{return Device{},ErrNotFound}
	last,err:=strconv.ParseInt(values["last_seen"],10,64);if err!=nil{return Device{},err}
	return Device{SiteID:values["site"],IdentityID:values["identity"],LastSeen:time.Unix(last,0)},nil
}
var refreshDeviceScript=redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
redis.call('HSET', KEYS[1], 'last_seen', ARGV[1])
redis.call('PEXPIRE', KEYS[1], ARGV[2])
return 1
`)
func(v *Valkey)RefreshDevice(ctx context.Context,id string,d Device,ttl time.Duration)error{
	result,err:=refreshDeviceScript.Run(ctx,v.client,[]string{v.deviceKey(id)},d.LastSeen.Unix(),ttl.Milliseconds()).Int()
	if err!=nil{return err};if result==0{return ErrNotFound};return nil
}
func(v *Valkey)DeleteDevice(ctx context.Context,id string)error{return v.client.Del(ctx,v.deviceKey(id)).Err()}
func(v *Valkey)Close()error{return v.client.Close()}

func decodeChallenge(values map[string]string)(Challenge,error){
	code,err:=base64.RawStdEncoding.DecodeString(values["code"]);if err!=nil{return Challenge{},err}
	attempts,err:=strconv.Atoi(values["attempts"]);if err!=nil{return Challenge{},err}
	return Challenge{SiteID:values["site"],IdentityID:values["identity"],CodeHash:code,ReturnURL:values["return"],Attempts:attempts},nil
}

