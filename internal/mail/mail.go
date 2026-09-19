package mail

import (
	"context"
	"fmt"
	"net"
	"net/smtp"
	"strings"
)

type Message struct {
	To string
	Subject string
	Text string
}

type Sender interface { Send(context.Context, Message) error }

type SMTP struct {
	Addr string
	Username string
	Password string
	From string
}

func (s SMTP) Send(ctx context.Context,m Message) error {
	host,_,err:=net.SplitHostPort(s.Addr);if err!=nil{return err}
	var auth smtp.Auth
	if s.Username!="" { auth=smtp.PlainAuth("",s.Username,s.Password,host) }
	headers:=[]string{
		"From: "+s.From,
		"To: "+m.To,
		"Subject: "+m.Subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
	}
	body:=strings.Join(headers,"\r\n")+"\r\n\r\n"+m.Text+"\r\n"
	done:=make(chan error,1)
	go func(){done<-smtp.SendMail(s.Addr,auth,s.From,[]string{m.To},[]byte(body))}()
	select{case <-ctx.Done():return ctx.Err();case err:=<-done:return err}
}

func OTPMessage(to,host,code string) Message {
	subject:="Website access code"
	if host!="" { subject=fmt.Sprintf("Website access code for %s",host) }
	return Message{To:to,Subject:subject,Text:fmt.Sprintf("Your access code is: %s\n\nThis code expires shortly. If you did not request it, you can ignore this email.",code)}
}
