package watch

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFileWatcherRenderDependenciesReuseAndReplace(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	root := filepath.Join(dir, "root")
	local := filepath.Join(root, "pod.yaml")
	first := filepath.Join(dir, "first", "pod.yaml")
	second := filepath.Join(dir, "second", "security")
	for _, path := range []string{local, first, second} {
		write(t, path, "kind: Pod\n")
	}

	ctx := t.Context()
	watcher, err := NewFileWatcher(ctx, root, FileWatcherOptions{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = watcher.Close() })
	watchers := []*FileWatcher{watcher}

	added, err := ReplaceRenderDependencies(ctx, watchers, map[string]struct{}{local: {}}, nil)
	require.NoError(t, err)
	require.False(t, added)
	require.Equal(t, []string{root}, watcher.fs.WatchList())

	added, err = ReplaceRenderDependencies(ctx, watchers, map[string]struct{}{first: {}}, nil)
	require.NoError(t, err)
	require.True(t, added)
	added, err = ReplaceRenderDependencies(ctx, watchers, map[string]struct{}{second: {}}, nil)
	require.NoError(t, err)
	require.True(t, added)
	require.ElementsMatch(t, []string{root, dir, filepath.Dir(second)}, watcher.fs.WatchList())

	write(t, second, "edited\n")
	select {
	case _, ok := <-watcher.Changes():
		require.True(t, ok, "the watcher ended: %v", watcher.Err())
	case <-time.After(waitTimeout):
		t.Fatal("editing an external dependency did not signal a change")
	}
}

func TestFileWatcherRetriesPartialDependencyRegistration(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	root, outside := filepath.Join(dir, "root"), filepath.Join(dir, "outside")
	write(t, filepath.Join(root, "pod.yaml"), "kind: Pod\n")
	dep := filepath.Join(outside, "security")
	write(t, dep, "old\n")
	watcher, err := newFileWatcher(root, FileWatcherOptions{})
	require.NoError(t, err)
	discardDeliveries(t, watcher)

	attempts := 0
	watcher.addWatch = func(path string) error {
		attempts++
		require.Equal(t, outside, path)
		require.NotContains(t, watcher.fs.WatchList(), outside, "a partial watch must be removed before retrying")
		err := watcher.fs.Add(path)
		if attempts == 1 && err == nil {
			return fs.ErrNotExist
		}
		return err
	}

	plan := make(dependencyDirectories)
	plan.addPath(dep)
	require.True(t, watcher.syncDependencies(plan, true))
	require.Equal(t, 2, attempts)
	require.Contains(t, watcher.fs.WatchList(), outside)
}

func TestFileWatcherMergesDependencyDirectoryAliases(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	actual := filepath.Join(dir, "Assets")
	first, second := filepath.Join(actual, "first"), filepath.Join(actual, "second")
	write(t, first, "old")
	write(t, second, "old")
	alias := filepath.Join(dir, "assets")
	if !sameDirectory(actual, alias) {
		t.Skip("the test filesystem is case-sensitive")
	}
	watcher, signals := startWatcher(t, dir, FileWatcherOptions{
		Exclude: func(_ string, isDir bool) bool { return !isDir },
	})
	_, err = ReplaceRenderDependencies(t.Context(), []*FileWatcher{watcher}, map[string]struct{}{
		first: {}, filepath.Join(alias, "second"): {},
	}, nil)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{dir, actual}, watcher.fs.WatchList())
	write(t, first, "new")
	write(t, second, "new")
	signals.waitFor(t, "first excluded dependency", is(first))
	signals.waitFor(t, "second excluded dependency", is(second))
}

func TestFileWatcherFollowsAncestorOfRenderDependency(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	root, shared := filepath.Join(dir, "overlay"), filepath.Join(dir, "shared")
	dependency := filepath.Join(shared, "platform", "base", "pod.yaml")
	write(t, filepath.Join(root, "pod.yaml"), "old")
	write(t, dependency, "old")
	watcher, signals := startWatcher(t, root, FileWatcherOptions{})
	watchers := []*FileWatcher{watcher}
	files := map[string]struct{}{dependency: {}}
	_, err = ReplaceRenderDependencies(t.Context(), watchers, files, nil)
	require.NoError(t, err)

	require.NoError(t, os.Rename(shared, filepath.Join(dir, "replaced")))
	signals.waitFor(t, "the moved ancestor", is(shared))
	write(t, dependency, "replacement")
	_, err = ReplaceRenderDependencies(t.Context(), watchers, files, nil)
	require.NoError(t, err)
	mark := signals.mark()
	write(t, dependency, "edited")
	signals.waitForAfter(t, mark, "the replacement dependency", is(dependency))
}

func TestFileWatcherChartSelectionSkipsIgnoredLink(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	chart := filepath.Join(dir, "chart")
	target := filepath.Join(dir, "artifact")
	write(t, filepath.Join(chart, ".helmignore"), "ignored/\n")
	write(t, filepath.Join(chart, "settings.tmp"), "chart data")
	write(t, filepath.Join(target, "large-tree", "data"), "fixture")
	if err := os.Symlink(target, filepath.Join(chart, "ignored")); err != nil && runtime.GOOS == "windows" {
		t.Skipf("directory symlink unavailable: %v", err)
	} else {
		require.NoError(t, err)
	}
	require.NoError(t, os.Symlink(filepath.Join(dir, "missing"), filepath.Join(chart, "dangling")))
	selection := make(dependencyDirectories)
	selection.addChart(t.Context(), chart, make(map[string]struct{}))
	require.True(t, selection[chart].chart)
	require.True(t, selection[chart].matches("settings.tmp"))
	require.True(t, selection[dir].matches("missing"))
	require.NotContains(t, selection, target)
	require.NotContains(t, selection, filepath.Join(target, "large-tree"))
}

func TestFileWatcherRereadsAfterLinkSnapshotChanges(t *testing.T) {
	watcher := &FileWatcher{}
	links := map[string]string{"current": "old"}
	dir := t.TempDir()
	plan := dependencyDirectories{dir: {names: map[string]string{"current": "current"}, links: links}}
	require.True(t, watcher.watchDependencyLinks(plan))
	require.False(t, watcher.watchDependencyLinks(plan))

	links["current"] = "new"
	require.True(t, watcher.watchDependencyLinks(plan))
	require.False(t, watcher.watchDependencyLinks(plan))

	delete(links, "current")
	require.True(t, watcher.watchDependencyLinks(plan))
	require.Contains(t, watcher.dependencyLinks, filepath.Join(dir, "current"))
	require.False(t, watcher.watchDependencyLinks(plan))
	require.True(t, watcher.watchDependencyLinks(nil))
	require.Nil(t, watcher.dependencyLinkCheck)
}
