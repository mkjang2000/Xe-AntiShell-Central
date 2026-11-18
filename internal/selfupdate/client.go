package selfupdate

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

const updaterSocket = "/run/xe-antishell-central-updater.sock"

// ClientError carries only the bounded worker response. Connection failures and
// invalid replies are distinct from an installation rejected by the worker.
type ClientError struct {
	StatusCode int
	Message    string
}

func (e *ClientError) Error() string { return e.Message }

var workerHTTP = &http.Client{
	Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", updaterSocket)
		},
		DisableCompression: true,
		IdleConnTimeout:    15 * time.Second,
	},
	Timeout:       3 * time.Minute,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func Current(ctx context.Context) (Status, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/status", nil)
	if err != nil {
		return Status{}, err
	}
	return workerRequest(workerHTTP, req, http.StatusOK)
}

func Apply(ctx context.Context, signed SignedManifest, rpm io.Reader) (Status, error) {
	if err := VerifyManifest(signed); err != nil {
		return Status{}, err
	}
	b, err := json.Marshal(signed)
	if err != nil {
		return Status{}, err
	}
	// The caller owns its source. Limit bytes even when it is a streaming download.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/apply", io.LimitReader(rpm, signed.Manifest.Size+1))
	if err != nil {
		return Status{}, err
	}
	req.ContentLength = signed.Manifest.Size
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Xeas-Central-Manifest", base64.RawURLEncoding.EncodeToString(b))
	return workerRequest(workerHTTP, req, http.StatusAccepted)
}

func workerRequest(client *http.Client, req *http.Request, want int) (Status, error) {
	res, err := client.Do(req)
	if err != nil {
		return Status{}, fmt.Errorf("central update worker unavailable: %w", err)
	}
	defer res.Body.Close()
	const limit = 16 << 10
	b, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil || len(b) > limit {
		return Status{}, errors.New("invalid central update worker response")
	}
	if res.StatusCode != want {
		var problem struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(b, &problem) != nil || problem.Error == "" {
			problem.Error = fmt.Sprintf("central update worker returned HTTP %d", res.StatusCode)
		}
		return Status{}, &ClientError{StatusCode: res.StatusCode, Message: problem.Error}
	}
	var s Status
	if json.Unmarshal(b, &s) != nil || s.State == "" {
		return Status{}, errors.New("invalid central update status")
	}
	return s, nil
}
