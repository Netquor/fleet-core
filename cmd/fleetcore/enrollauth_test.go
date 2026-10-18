package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEnrollAuthorizer(t *testing.T) {
	req := func(target string, hdr map[string]string) *http.Request {
		r := httptest.NewRequest("GET", target, nil)
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		return r
	}
	if enrollAuthorizer("", "", true) != nil {
		t.Error("open enrollment should have no authorizer")
	}
	closed := enrollAuthorizer("", "", false)
	if err := closed(req("/enroll", nil)); err == nil {
		t.Error("enrollment with no secret, URL or open flag was allowed")
	}
	sec := enrollAuthorizer("s3cret-code", "", false)
	for name, r := range map[string]*http.Request{
		"query":  req("/enroll?code=s3cret-code", nil),
		"bearer": req("/enroll", map[string]string{"Authorization": "Bearer s3cret-code"}),
	} {
		if err := sec(r); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	basic := req("/enroll", nil)
	basic.SetBasicAuth("anyone", "s3cret-code")
	if err := sec(basic); err != nil {
		t.Errorf("basic: %v", err)
	}
	if err := sec(req("/enroll?code=nope", nil)); err == nil {
		t.Error("a wrong code was accepted")
	}
	if err := sec(req("/enroll", nil)); err == nil {
		t.Error("no code was accepted")
	}
	gate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Session") == "ok" {
			return
		}
		w.WriteHeader(401)
	}))
	defer gate.Close()
	fwd := enrollAuthorizer("", gate.URL, false)
	if err := fwd(req("/enroll", map[string]string{"X-Session": "ok"})); err != nil {
		t.Errorf("forward auth: %v", err)
	}
	if err := fwd(req("/enroll", nil)); err == nil {
		t.Error("forward auth let an unauthenticated request through")
	}
}
