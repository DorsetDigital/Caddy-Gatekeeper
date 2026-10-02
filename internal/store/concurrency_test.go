package store

import (
	"context"
	"crypto/sha256"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConcurrentChallengeRedemptionAllowsExactlyOneSuccess(t *testing.T) {
	runConcurrentChallengeTest(t, func() Store { return NewMemory() })
}

func runConcurrentChallengeTest(t *testing.T,newStore func() Store){
	t.Helper()
	s:=newStore();defer s.Close()
	ctx:=context.Background();code:=sha256.Sum256([]byte("123456"))
	if err:=s.CreateChallenge(ctx,"race",Challenge{IdentityID:"identity",CodeHash:code[:],ReturnURL:"/admin"},time.Minute);err!=nil{t.Fatal(err)}
	var success atomic.Int32
	var unexpected atomic.Int32
	var wg sync.WaitGroup
	for i:=0;i<100;i++{
		wg.Add(1);go func(){defer wg.Done();result,err:=s.VerifyChallenge(ctx,"race",code[:],3);if err!=nil{unexpected.Add(1);return};switch result.Status{case VerifySuccess:success.Add(1);case VerifyNotFound:default:unexpected.Add(1)}}()
	}
	wg.Wait()
	if success.Load()!=1{t.Fatalf("successful redemptions=%d, want 1",success.Load())}
	if unexpected.Load()!=0{t.Fatalf("unexpected results=%d",unexpected.Load())}
}

func TestConcurrentInvalidAttemptsCannotExceedLimit(t *testing.T){
	s:=NewMemory();defer s.Close();ctx:=context.Background()
	good:=sha256.Sum256([]byte("123456"));bad:=sha256.Sum256([]byte("000000"))
	if err:=s.CreateChallenge(ctx,"attempt-race",Challenge{IdentityID:"identity",CodeHash:good[:],ReturnURL:"/admin"},time.Minute);err!=nil{t.Fatal(err)}
	var wg sync.WaitGroup
	var exhausted atomic.Int32
	for i:=0;i<100;i++{wg.Add(1);go func(){defer wg.Done();r,err:=s.VerifyChallenge(ctx,"attempt-race",bad[:],3);if err==nil&&r.Status==VerifyExhausted{exhausted.Add(1)}}()}
	wg.Wait()
	if exhausted.Load()!=1{t.Fatalf("exhausted results=%d, want 1",exhausted.Load())}
	if _,err:=s.GetChallenge(ctx,"attempt-race");err!=ErrNotFound{t.Fatalf("challenge remains after concurrent failures: %v",err)}
}
