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
	once    sync.Once
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
	select {
	case d.queue <- message:
		return nil
	default:
		return ErrQueueFull
	}
}

func (d *AsyncDispatcher) Close() {
	d.once.Do(func() {
		close(d.queue)
		d.wg.Wait()
	})
}

func (d *AsyncDispatcher) worker() {
	defer d.wg.Done()

	for message := range d.queue {
		ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
		err := d.sender.Send(ctx, message)
		cancel()

		if err != nil {
			log.Printf("gatekeeper: OTP delivery failed: %v", err)
			continue
		}

		log.Printf("gatekeeper: OTP delivery accepted by SMTP server")
	}
}
