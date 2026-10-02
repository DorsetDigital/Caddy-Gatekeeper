package access

import "testing"

func TestMatcher(t *testing.T){
	m:=NewMatcher([]Rule{{Type:RuleEmail,Value:"contractor@gmail.com"},{Type:RuleDomain,Value:"Example.COM"}})
	tests:=map[string]bool{
		"contractor@gmail.com":true,
		"CONTRACTOR@GMAIL.COM":true,
		"fred@example.com":true,
		"FRED@EXAMPLE.COM":true,
		"fred@sales.example.com":false,
		"fred@notexample.com":false,
		"other@gmail.com":false,
		"not-an-email":false,
	}
	for identity,want:=range tests{if got:=m.Allowed(identity);got!=want{t.Errorf("Allowed(%q)=%v, want %v",identity,got,want)}}
}
