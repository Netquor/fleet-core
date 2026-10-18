package main

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"
)

// enrollAuthorizer decides who may download an enrollment profile (which carries a one-use SCEP challenge). One of three modes:
//
//   - a shared enrollment secret, given as ?code=, as a Bearer token, or as the basic-auth password;
//   - a forward-authentication URL: the profile request's headers and query are sent there and a 2xx answer lets it through, so a proxy or an identity provider's gateway decides;
//   - open, only when asked for with -enroll-open (anyone who can reach the server gets a profile).
//
// With none of them the endpoint refuses, so a server is never open by accident. Both a secret and a URL may be given; either then suffices.
func enrollAuthorizer(secret, forwardURL string, open bool) func(*http.Request) error {
	if open {
		return nil
	}
	client := &http.Client{Timeout: 10 * time.Second}
	return func(r *http.Request) error {
		if secret != "" {
			got := r.URL.Query().Get("code")
			if auth := r.Header.Get("Authorization"); got == "" && strings.HasPrefix(auth, "Bearer ") {
				got = strings.TrimPrefix(auth, "Bearer ")
			}
			if _, pass, ok := r.BasicAuth(); got == "" && ok {
				got = pass
			}
			if got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(secret)) == 1 {
				return nil
			}
		}
		if forwardURL != "" {
			req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, forwardURL, nil)
			if err != nil {
				return err
			}
			req.Header = r.Header.Clone()
			req.Header.Set("X-Forwarded-Uri", r.URL.RequestURI())
			req.Header.Set("X-Forwarded-Method", r.Method)
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			resp.Body.Close()
			if resp.StatusCode/100 == 2 {
				return nil
			}
		}
		if secret == "" && forwardURL == "" {
			return errors.New("enrollment is closed: start the server with -enroll-secret, -enroll-auth-url or -enroll-open")
		}
		return errors.New("an enrollment code is required")
	}
}
