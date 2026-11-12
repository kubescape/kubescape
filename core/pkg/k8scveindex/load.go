package k8scveindex

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"syscall"
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

var (
	// ErrFeedNotRegular is returned when a local feed file is not a regular file.
	ErrFeedNotRegular = errors.New("kubernetes cve feed is not a regular file")
	// ErrFeedTooLarge is returned when a feed file or response exceeds the maximum allowed size.
	ErrFeedTooLarge = errors.New("kubernetes cve feed exceeds maximum size limit")
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

// openFeedFile opens path for reading and rejects anything but a regular file.
// A pre-open stat check prevents opening device nodes (e.g. tape or character devices).
// O_NONBLOCK keeps opening a FIFO from waiting for a writer, and descriptor-based
// validation ensures a path swapped after stat cannot slip past. The original path
// is passed directly to preserve symlink traversal semantics.
func openFeedFile(path string) (*os.File, error) {
	if strings.TrimSpace(path) == "" {
		return nil, os.ErrNotExist
	}
	statInfo, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if statInfo.IsDir() {
		return nil, fmt.Errorf("%q is a directory, not a file: %w", path, ErrFeedNotRegular)
	}
	if !statInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %q", ErrFeedNotRegular, path)
	}

	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if info.IsDir() {
		file.Close()
		return nil, fmt.Errorf("%q is a directory, not a file: %w", path, ErrFeedNotRegular)
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, fmt.Errorf("%w: %q", ErrFeedNotRegular, path)
	}
	return file, nil
}

// Load returns the applicability index. A failed refresh falls back to the
// embedded copy; a LocalPath that cannot be read is an error, since the user
// asked for that file explicitly.
func Load(ctx context.Context, opts Options) (*Index, Source, error) {
	if opts.LocalPath != "" {
		file, err := openFeedFile(opts.LocalPath)
		if err != nil {
			return nil, "", fmt.Errorf("open kubernetes cve feed: %w", err)
		}
		defer file.Close()

		info, err := file.Stat()
		if err == nil && info.Size() > maxFeedSize {
			return nil, "", fmt.Errorf("%w: %q exceeds the %d byte limit", ErrFeedTooLarge, opts.LocalPath, maxFeedSize)
		}

		data, err := io.ReadAll(io.LimitReader(file, maxFeedSize+1))
		if err != nil {
			return nil, "", fmt.Errorf("read kubernetes cve feed: %w", err)
		}
		if int64(len(data)) > maxFeedSize {
			return nil, "", fmt.Errorf("%w: %q exceeds the %d byte limit", ErrFeedTooLarge, opts.LocalPath, maxFeedSize)
		}

		ix, err := Parse(bytes.NewReader(data))
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

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedSize+1))
	if err != nil {
		return nil, fmt.Errorf("read kubernetes cve feed: %w", err)
	}
	if int64(len(data)) > maxFeedSize {
		return nil, fmt.Errorf("%w: remote response exceeds the %d byte limit", ErrFeedTooLarge, maxFeedSize)
	}

	return Parse(bytes.NewReader(data))
}
