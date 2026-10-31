//go:build !darwin && !linux

package peertransport

import "errors"

func mkfifo(string) error {
	return errors.New("mkfifo not supported on this platform")
}
