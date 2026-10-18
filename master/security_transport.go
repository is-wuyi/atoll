package master

import "net/http"

type securityRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn securityRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }
