package central

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/mkjang2000/Xe-AntiShell-Central/internal/githubrelease"
)

const updateGitHubRepository = "mkjang2000/Xe-AntiShell"
const updateGitHubAPI = "https://api.github.com/repos/" + updateGitHubRepository + "/releases"

var errUpdateGitHub = githubrelease.ErrUnavailable

type updateGitHubClient struct {
	http   *http.Client
	mu     sync.Mutex
	cached updateGitHubCatalog
	now    func() time.Time
}

func newUpdateGitHubClient() *updateGitHubClient {
	return &updateGitHubClient{http: githubrelease.NewHTTPClient(), now: time.Now}
}

func (c *updateGitHubClient) get(ctx context.Context, raw string) (*http.Response, error) {
	return githubrelease.Get(ctx, c.http, raw)
}

func (c *updateGitHubClient) json(ctx context.Context, raw string, maximum int64, target any) error {
	return githubrelease.JSON(ctx, c.http, raw, maximum, target)
}
