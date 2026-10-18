package access

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type observedBody struct {
	io.Reader
	closed bool
}

func (b *observedBody) Close() error { b.closed = true; return nil }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }

func TestAuthorizationFailureClosesBody(t *testing.T) {
	body := &observedBody{Reader: strings.NewReader("upload")}
	req, err := http.NewRequest(http.MethodPut, "https://node.example/objects/1", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer original")
	denied := errors.New("denied")
	sent := false
	tr := &Transport{
		Base: roundTripFunc(func(*http.Request) (*http.Response, error) {
			sent = true
			return nil, nil
		}),
		Authorize: func(clone *http.Request) error {
			clone.Header.Set("Authorization", "Bearer replacement")
			return denied
		},
	}
	if _, err := tr.RoundTrip(req); !errors.Is(err, denied) {
		t.Fatalf("authorization error: %v", err)
	}
	if sent || !body.closed {
		t.Fatalf("denied request sent=%v, body closed=%v", sent, body.closed)
	}
	if req.Header.Get("Authorization") != "Bearer original" {
		t.Fatal("authorization mutated the caller's headers")
	}
}

func TestAuthorizedRequestKeepsBodyAndHeadersIsolated(t *testing.T) {
	body := &observedBody{Reader: strings.NewReader("upload")}
	req, err := http.NewRequest(http.MethodPut, "https://node.example/objects/1", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer original")
	tr := &Transport{
		Base: roundTripFunc(func(clone *http.Request) (*http.Response, error) {
			if body.closed || clone.Header.Get("Authorization") != "Bearer ticket" {
				t.Fatal("authorized request did not reach transport intact")
			}
			got, err := io.ReadAll(clone.Body)
			clone.Body.Close()
			if err != nil || string(got) != "upload" {
				t.Fatalf("request body: %q %v", got, err)
			}
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
		}),
		Authorize: func(clone *http.Request) error {
			clone.Header.Set("Authorization", "Bearer ticket")
			return nil
		},
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if req.Header.Get("Authorization") != "Bearer original" || !body.closed {
		t.Fatal("request ownership or body cleanup changed")
	}
}
