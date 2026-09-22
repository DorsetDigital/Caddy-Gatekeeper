package mail

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type blockingSender struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *blockingSender) Send(ctx context.Context, _ Message) error {
	s.once.Do(func(){close(s.started)})
	select {
	case <-s.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestAsyncDispatcherQueueIsBounded(t *testing.T) {
	sender:=&blockingSender{started:make(chan struct{}),release:make(chan struct{})}
	dispatcher:=NewAsyncDispatcher(sender,1,1,time.Second)
	defer func(){close(sender.release);dispatcher.Close()}()

	if err:=dispatcher.Enqueue(Message{To:"one@example.test"});err!=nil{t.Fatalf("first enqueue: %v",err)}
	select {
	case <-sender.started:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}

	if err:=dispatcher.Enqueue(Message{To:"two@example.test"});err!=nil{t.Fatalf("second enqueue: %v",err)}
	if err:=dispatcher.Enqueue(Message{To:"three@example.test"});!errors.Is(err,ErrQueueFull){
		t.Fatalf("third enqueue error=%v, want ErrQueueFull",err)
	}
}

type timeoutSender struct {
	done chan error
}

func (s *timeoutSender) Send(ctx context.Context, _ Message) error {
	<-ctx.Done()
	s.done<-ctx.Err()
	return ctx.Err()
}

func TestAsyncDispatcherAppliesDeliveryTimeout(t *testing.T) {
	sender:=&timeoutSender{done:make(chan error,1)}
	dispatcher:=NewAsyncDispatcher(sender,1,1,20*time.Millisecond)
	defer dispatcher.Close()

	if err:=dispatcher.Enqueue(Message{To:"one@example.test"});err!=nil{t.Fatal(err)}

	select {
	case err:=<-sender.done:
		if !errors.Is(err,context.DeadlineExceeded){t.Fatalf("error=%v, want deadline exceeded",err)}
	case <-time.After(250*time.Millisecond):
		t.Fatal("delivery timeout did not fire")
	}
}
