package mail

import (
	"context"
	"log"
	"sync"
	"time"
)

type AsyncDispatcher struct {
	sender  Sender
	queue   chan Message
	timeout time.Duration
	wg      sync.WaitGroup

	mu     sync.RWMutex
	closed bool
}

func NewAsyncDispatcher(sender Sender, workers, queueSize int, timeout time.Duration) *AsyncDispatcher {
	if workers < 1 {
		workers = 1
	}
	if queueSize < 1 {
		queueSize = 1
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	d := &AsyncDispatcher{
		sender:  sender,
		queue:   make(chan Message, queueSize),
		timeout: timeout,
	}

	d.wg.Add(workers)
	for i := 0; i < workers; i++ {
		go d.worker()
	}

	return d
}

func (d *AsyncDispatcher) Enqueue(message Message) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.closed {
		return ErrDispatcherClosed
	}

	select {
	case d.queue <- message:
		return nil
	default:
		return ErrQueueFull
	}
}

func (d *AsyncDispatcher) Shutdown(ctx context.Context) error {
	d.mu.Lock()
	if !d.closed {
		d.closed = true
		close(d.queue)
	}
	d.mu.Unlock()

	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *AsyncDispatcher) worker() {
	defer d.wg.Done()

	for message := range d.queue {
		ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
		err := d.sender.Send(ctx, message)
		cancel()

		if err != nil {
			log.Printf("gatekeeper: OTP delivery failed site=%q host=%q: %v", message.SiteID, message.Host, err)
			continue
		}

		log.Printf("gatekeeper: OTP delivery accepted by SMTP server site=%q host=%q", message.SiteID, message.Host)
	}
}
