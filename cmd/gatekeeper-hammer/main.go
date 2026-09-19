package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

func main(){
	target:=flag.String("url","http://localhost:8080/admin","URL to hammer")
	requests:=flag.Int("n",10000,"total requests")
	concurrency:=flag.Int("c",100,"concurrent workers")
	flag.Parse()
	if *requests<1||*concurrency<1{panic("n and c must be positive")}
	client:=&http.Client{Timeout:10*time.Second,CheckRedirect:func(_ *http.Request,_ []*http.Request)error{return http.ErrUseLastResponse}}
	jobs:=make(chan int);var ok,failed atomic.Int64;var wg sync.WaitGroup
	start:=time.Now()
	for i:=0;i<*concurrency;i++{wg.Add(1);go func(){defer wg.Done();for range jobs{resp,err:=client.Get(*target);if err!=nil{failed.Add(1);continue};_,_=io.Copy(io.Discard,resp.Body);_ = resp.Body.Close();if resp.StatusCode>=200&&resp.StatusCode<400{ok.Add(1)}else{failed.Add(1)}}}()}
	for i:=0;i<*requests;i++{jobs<-i};close(jobs);wg.Wait();elapsed:=time.Since(start)
	fmt.Printf("Gatekeeper hammer\n-----------------\nRequests:   %d\nConcurrency:%d\nSuccessful: %d\nFailed:     %d\nElapsed:    %s\nRate:       %.1f req/s\n",*requests,*concurrency,ok.Load(),failed.Load(),elapsed,float64(*requests)/elapsed.Seconds())
	if failed.Load()>0{panic("unexpected request failures")}
}
