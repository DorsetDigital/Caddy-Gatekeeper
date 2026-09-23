package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
)

type Message struct {
	To string
	Subject string
	Text string
	SiteID string
	Host string
}

type Sender interface {
	Send(context.Context, Message) error
}

type Dispatcher interface {
	Enqueue(Message) error
	Shutdown(context.Context) error
}

type SMTP struct {
	Addr string
	Username string
	Password string
	From string
}

func (s SMTP) Send(ctx context.Context, m Message) error {
	host, _, err := net.SplitHostPort(s.Addr)
	if err != nil {
		return err
	}

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", s.Addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return err
		}
	}

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer client.Close()

	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
		}); err != nil {
			return err
		}
	}

	if s.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", s.Username, s.Password, host)); err != nil {
			return err
		}
	}

	if err := client.Mail(s.From); err != nil {
		return err
	}
	if err := client.Rcpt(m.To); err != nil {
		return err
	}

	writer, err := client.Data()
	if err != nil {
		return err
	}

	headers := []string{
		"From: " + s.From,
		"To: " + m.To,
		"Subject: " + m.Subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
	}
	body := strings.Join(headers, "\r\n") + "\r\n\r\n" + m.Text + "\r\n"

	if _, err := writer.Write([]byte(body)); err != nil {
		_ = writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	if err := client.Quit(); err != nil {
		return err
	}

	return nil
}

var (
	ErrQueueFull = errors.New("SMTP delivery queue full")
	ErrDispatcherClosed = errors.New("SMTP delivery dispatcher closed")
)

func OTPMessage(to,host,code string) Message {
	subject:="Website access code"
	if host!="" { subject=fmt.Sprintf("Website access code for %s",host) }
	return Message{To:to,Subject:subject,Text:fmt.Sprintf("Your access code is: %s\n\nThis code expires shortly. If you did not request it, you can ignore this email.",code),Host:host}
}
