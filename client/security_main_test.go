package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type denialBody struct {
	reads  int
	closes int
}

func (b *denialBody) Read([]byte) (int, error) { b.reads++; return 0, io.EOF }
func (b *denialBody) Close() error             { b.closes++; return nil }

func TestSecureDenialClosesUploadBody(t *testing.T) {
	for _, kind := range []string{"url", "host", "scheme", "no-session", "no-space", "ticket-denied"} {
		t.Run(kind, func(t *testing.T) {
			rt := &recordingRT{handler: func(req *http.Request) (*http.Response, error) {
				req.Body.Close()
				return &http.Response{StatusCode: http.StatusForbidden, Body: http.NoBody, Header: make(http.Header)}, nil
			}}
			c := newRecordingSecureClient(t, rt, "session", 7)
			body := &denialBody{}
			req, err := http.NewRequest(http.MethodPut, "https://node.example/objects/1", body)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "url":
				req.URL.Fragment = "invalid"
			case "host":
				req.Host = "other.example"
			case "scheme":
				req.URL.Scheme = "http"
			case "no-session":
				c.SetSession("")
			case "no-space":
				c.UseSpace(0)
			}
			if _, err := c.HTTP.Do(req); err == nil {
				t.Fatal("denied upload unexpectedly succeeded")
			}
			if body.reads != 0 || body.closes != 1 {
				t.Fatalf("denied body reads=%d closes=%d, want 0 and 1", body.reads, body.closes)
			}
		})
	}
}

func TestSecureLoginRejectsInvalidIdentityAndToken(t *testing.T) {
	for _, kind := range []string{"invalid-space", "zero-user", "whitespace-token", "oversize-token"} {
		t.Run(kind, func(t *testing.T) {
			result := LoginResult{Token: "new-session", ExpiresAt: time.Now().Add(time.Hour), User: UserInfo{ID: 1, Username: "alice", PersonalSpaceID: 7}}
			switch kind {
			case "invalid-space":
				result.Space = &SpaceInfo{}
			case "zero-user":
				result.User.ID = 0
			case "whitespace-token":
				result.Token = "bad token"
			case "oversize-token":
				result.Token = strings.Repeat("x", 513)
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				json.NewEncoder(w).Encode(result)
			}))
			defer srv.Close()
			c, err := NewSecure(srv.URL, nil, true)
			if err != nil {
				t.Fatal(err)
			}
			c.SetSession("prior-session")
			c.UseSpace(7)
			if _, err := c.Login(context.Background(), "alice", "password"); err == nil {
				t.Fatal("malformed login response was accepted")
			}
			token, space, selected := c.sec.snapshot()
			if token != "prior-session" || space != 7 || !selected {
				t.Fatal("malformed login response replaced the previous session")
			}
		})
	}
}
