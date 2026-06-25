// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDelegatedValidator(t *testing.T) {
	want := Identity{Subject: "alice", Expiry: time.Unix(100, 0)}
	v := DelegatedValidator{ValidateFunc: func(_ context.Context, tok string) (Identity, error) {
		if tok != "tok" {
			return Identity{}, ErrTokenInvalid
		}
		return want, nil
	}}
	got, err := v.Validate(context.Background(), "tok")
	if err != nil || got.Subject != "alice" {
		t.Fatalf("got %+v, %v", got, err)
	}
	if _, err := v.Validate(context.Background(), "bad"); !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("bad token: got %v, want ErrTokenInvalid", err)
	}
}

func TestDelegatedValidatorNilFunc(t *testing.T) {
	if _, err := (DelegatedValidator{}).Validate(context.Background(), "x"); err == nil {
		t.Error("nil ValidateFunc must error")
	}
}
