package console

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLimiterAtomicReservationsAndExpiry(t *testing.T) {
	l := newLoginLimiter()
	now := time.Unix(1_700_000_000, 0)
	var accepted atomic.Int32
	var workers sync.WaitGroup
	for i := 0; i < 50; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if l.allow("192.0.2.1", now) {
				accepted.Add(1)
			}
		}()
	}
	workers.Wait()
	if accepted.Load() != loginIPLimit {
		t.Fatalf("concurrent allowance=%d expected=%d", accepted.Load(), loginIPLimit)
	}
	if !l.allow("192.0.2.1", now.Add(loginWindow)) {
		t.Fatal("expired IP allowance was not renewed")
	}
}

func TestLimiterGlobalBoundAndCapacity(t *testing.T) {
	l := newLoginLimiter()
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < loginGlobalLimit; i++ {
		if !l.allow(fmt.Sprintf("192.0.2.%d", i), now) {
			t.Fatalf("global attempt %d unexpectedly rejected", i)
		}
	}
	if l.allow("198.51.100.1", now) {
		t.Fatal("new IP bypassed global rate limit")
	}
	l.global = loginAttempt{start: now}
	for i := len(l.attempts); i < loginIPCapacity; i++ {
		l.attempts[fmt.Sprintf("entry-%d", i)] = loginAttempt{start: now}
	}
	if l.allow("new-IP", now) || len(l.attempts) != loginIPCapacity {
		t.Fatal("limiter exceeded bounded source-IP capacity")
	}
	if !l.allow("new-IP", now.Add(loginWindow)) || len(l.attempts) != 1 {
		t.Fatal("expired limiter entries were not removed")
	}
}
