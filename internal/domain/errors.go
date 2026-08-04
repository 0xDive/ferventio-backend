package domain

import "errors"

var (
	ErrRegistrationNotFound = errors.New("registration not found")
	ErrDeviceSecretMismatch = errors.New("device secret mismatch")
)
