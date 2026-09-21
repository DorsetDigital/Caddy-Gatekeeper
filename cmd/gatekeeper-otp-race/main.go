package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

func main(){
	target:=flag.String("url","http://localhost:8080/.gatekeeper/verify","verification endpoint")
	id:=flag.String("id","","challenge ID")
	code:=flag.String("code","","OTP code")
	n:=flag.Int("n",100,"concurrent submissions")
	mode:=flag.String("mode","valid","valid or invalid")
	flag.Parse()
	if *id==""||*code==""{panic("-id and -code are required")};if *mode!="valid"&&*mode!="invalid"{panic("-mode must be valid or invalid")}
	start:=make(chan struct{});results:=make(chan string,*n);var wg sync.WaitGroup
	for i:=0;i<*n;i++{wg.Add(1);go func(){defer wg.Done();<-start;form:=url.Values{"id":{*id},"code":{*code}};req,err:=http.NewRequest(http.MethodPost,*target,strings.NewReader(form.Encode()));if err!=nil{results<-"request-error";return};req.Header.Set("Content-Type","application/x-www-form-urlencoded");client:=&http.Client{CheckRedirect:func(_ *http.Request,_ []*http.Request)error{return http.ErrUseLastResponse}};resp,err:=client.Do(req);if err!=nil{results<-"transport-error";return};body,_:=io.ReadAll(io.LimitReader(resp.Body,4096));_ = resp.Body.Close();location:=resp.Header.Get("Location");if resp.StatusCode==http.StatusFound&&location!=""{results<-"redirect:"+location;return};if strings.Contains(string(body),"Request a new code"){results<-"consumed";return};results<-fmt.Sprintf("status:%d",resp.StatusCode)}()}
	close(start);wg.Wait();close(results)
	counts:=map[string]int{};for r:=range results{counts[r]++}
	fmt.Println("Concurrent OTP redemption");fmt.Println("-------------------------");fmt.Printf("Requests: %d\n",*n);for k,v:=range counts{fmt.Printf("%s: %d\n",k,v)}
	success:=0;for k,v:=range counts{if strings.HasPrefix(k,"redirect:"){success+=v}}
	if *mode=="valid"{if success!=1{panic(fmt.Sprintf("successful redemptions=%d, want exactly 1",success))};fmt.Println("PASS: exactly one OTP redemption succeeded");return}
	if success!=0{panic(fmt.Sprintf("successful redemptions=%d, want 0",success))}
	fmt.Println("PASS: no invalid OTP submission authenticated; challenge should now be exhausted")
}
