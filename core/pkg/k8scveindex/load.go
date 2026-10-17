package k8scveindex

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

const (
	FeedURL = "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json"

	// DefaultMaxAge is how old the index may get before Stale reports it.
	DefaultMaxAge = 7 * 24 * time.Hour

	maxFeedSize  = 16 << 20
	fetchTimeout = 30 * time.Second
)

//go:generate curl -sSfL https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json -o data/official-cve-feed.json
//go:embed data/official-cve-feed.json
var embeddedFeed []byte

type Source string

const (
	SourceLocal    Source = "local"
	SourceRemote   Source = "remote"
	SourceEmbedded Source = "embedded"
)

type Options struct {
	// LocalPath, when set, is the only source used, for air-gapped scans.
	LocalPath string
	// SkipUpdate uses the embedded copy without contacting the feed.
	SkipUpdate bool
	URL        string
	Client     *http.Client
}

// Load returns the applicability index. A failed refresh falls back to the
// embedded copy; a LocalPath that cannot be read is an error, since the user
// asked for that file explicitly.
func Load(ctx context.Context, opts Options) (*Index, Source, error) {
	if opts.LocalPath != "" {
		f, err := os.Open(opts.LocalPath)
		if err != nil {
			return nil, "", fmt.Errorf("open kubernetes cve feed: %w", err)
		}
		defer f.Close()
		ix, err := Parse(io.LimitReader(f, maxFeedSize))
		if err != nil {
			return nil, "", err
		}
		return ix, SourceLocal, nil
	}

	if !opts.SkipUpdate {
		ix, err := fetch(ctx, opts)
		if err == nil {
			return ix, SourceRemote, nil
		}
		logger.L().Ctx(ctx).Warning("Failed to refresh the Kubernetes CVE feed, using the embedded copy", helpers.Error(err))
	}

	ix, err := Parse(bytes.NewReader(embeddedFeed))
	if err != nil {
		return nil, "", err
	}
	return ix, SourceEmbedded, nil
}

func fetch(ctx context.Context, opts Options) (*Index, error) {
	url := opts.URL
	if url == "" {
		url = FeedURL
	}
	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: fetchTimeout}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch kubernetes cve feed: unexpected status %s", resp.Status)
	}
	return Parse(io.LimitReader(resp.Body, maxFeedSize))
}
