package console

import (
	"sync"
	"time"
)

const (
	loginWindow      = 5 * time.Minute
	loginIPLimit     = 5
	loginGlobalLimit = 30
	loginIPCapacity  = 1024
)

type loginAttempt struct {
	count int
	start time.Time
}

type loginLimiter struct {
	mu       sync.Mutex
	global   loginAttempt
	attempts map[string]loginAttempt
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{attempts: make(map[string]loginAttempt)}
}

// All attempts count, including successful and malformed requests. Reservation
// is atomic, so simultaneous requests cannot bypass the per-IP allowance.
func (l *loginLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.global.start) >= loginWindow {
		l.global = loginAttempt{start: now}
	}
	if l.global.count >= loginGlobalLimit {
		return false
	}
	for key, attempt := range l.attempts {
		if now.Sub(attempt.start) >= loginWindow {
			delete(l.attempts, key)
		}
	}
	attempt, exists := l.attempts[ip]
	if !exists {
		if len(l.attempts) >= loginIPCapacity {
			return false
		}
		attempt = loginAttempt{start: now}
	}
	if attempt.count >= loginIPLimit {
		return false
	}
	attempt.count++
	l.global.count++
	l.attempts[ip] = attempt
	return true
}
