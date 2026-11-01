package imapmail

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestDialRetriesDNSBeforeConnection(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	calls := 0
	got, err := dialWithDNSRetry(context.Background(), func(context.Context) (net.Conn, error) {
		calls++
		if calls == 1 {
			return nil, fmt.Errorf("dial: %w", &net.DNSError{Err: "no such host", Name: "example.invalid", IsNotFound: true})
		}
		return client, nil
	}, []time.Duration{0, 0})
	if err != nil || got != client || calls != 2 {
		t.Fatalf("got connection %v, error %v, calls %d; want connection after two calls", got != nil, err, calls)
	}
}

func TestDialDNSRetriesExhaustedPreservesLastError(t *testing.T) {
	last := &net.DNSError{Err: "no such host", Name: "example.invalid", IsNotFound: true}
	calls := 0
	conn, err := dialWithDNSRetry(context.Background(), func(context.Context) (net.Conn, error) {
		calls++
		return nil, fmt.Errorf("dial: %w", last)
	}, []time.Duration{0, 0})
	if conn != nil || calls != 3 || !errors.Is(err, last) {
		t.Fatalf("got connection %v, error %v, calls %d; want last DNS error after three calls", conn != nil, err, calls)
	}
}

func TestDialDoesNotRetryOtherFailures(t *testing.T) {
	for _, original := range []error{
		errors.New("certificate validation failed"),
		&net.OpError{Op: "dial", Err: errors.New("connection refused")},
		&net.DNSError{Err: "permanent resolver failure", Name: "example.invalid"},
	} {
		calls := 0
		_, err := dialWithDNSRetry(context.Background(), func(context.Context) (net.Conn, error) {
			calls++
			return nil, original
		}, []time.Duration{0, 0})
		if calls != 1 || !errors.Is(err, original) {
			t.Fatalf("got error %v after %d calls; want original error and one call", err, calls)
		}
	}
}

func TestDialDNSBackoffHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	cause := errors.New("caller stopped")
	dialed := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		_, err := dialWithDNSRetry(ctx, func(context.Context) (net.Conn, error) {
			close(dialed)
			return nil, &net.DNSError{Err: "temporary failure", IsTemporary: true}
		}, []time.Duration{time.Hour})
		result <- err
	}()
	<-dialed
	cancel(cause)
	select {
	case err := <-result:
		if !errors.Is(err, cause) {
			t.Fatalf("got %v; want cancellation cause", err)
		}
	case <-time.After(time.Second):
		t.Fatal("backoff did not stop after cancellation")
	}
}

func TestDialDoesNotStartWhenContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	_, err := dialWithDNSRetry(ctx, func(context.Context) (net.Conn, error) {
		calls++
		return nil, nil
	}, []time.Duration{0})
	if calls != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v after %d calls; want cancellation and no call", err, calls)
	}
}
