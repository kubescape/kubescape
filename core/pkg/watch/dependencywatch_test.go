package watch

import (
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/stretchr/testify/require"
	"helm.sh/helm/v3/pkg/chart/loader"
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
	require.True(t, added, "a new selection needs a reread even in an existing watch")
	added, err = ReplaceRenderDependencies(ctx, watchers, map[string]struct{}{local: {}}, nil)
	require.NoError(t, err)
	require.False(t, added, "an unchanged selection needs no additional reread")
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
	if runtime.GOOS == "windows" {
		t.Skip("Windows cannot rename a directory with open watch handles in its subtree")
	}
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

func TestFileWatcherReportsDependencyPermissionChange(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	root := filepath.Join(dir, "overlay")
	selected := filepath.Join(dir, "base", "pod.yaml")
	unrelated := filepath.Join(dir, "base", "other.yaml")
	write(t, filepath.Join(root, "kustomization.yaml"), "resources: []")
	write(t, selected, "kind: Pod")
	write(t, unrelated, "kind: Pod")
	watcher, err := newFileWatcher(root, FileWatcherOptions{})
	require.NoError(t, err)
	discardDeliveries(t, watcher)
	plan := make(dependencyDirectories)
	plan.addPath(selected)
	plan.addPath(filepath.Dir(selected))
	require.True(t, watcher.syncDependencies(plan, true))

	require.NoError(t, watcher.handle(fsnotify.Event{Name: unrelated, Op: fsnotify.Chmod}))
	require.Empty(t, watcher.changes)
	for _, path := range []string{selected, filepath.Dir(selected)} {
		event := fsnotify.Event{Name: path, Op: fsnotify.Chmod}
		require.NoError(t, watcher.handle(event))
		require.Empty(t, watcher.changes, "a read can send an attribute event with unchanged mode")

		info, err := os.Stat(path)
		require.NoError(t, err)
		mode := info.Mode().Perm()
		t.Cleanup(func() { require.NoError(t, os.Chmod(path, mode)) })
		require.NoError(t, os.Chmod(path, mode&^0o222))
		require.NoError(t, watcher.handle(event))
		require.Len(t, watcher.changes, 1)
		<-watcher.changes

		require.NoError(t, watcher.handle(event))
		require.Empty(t, watcher.changes)
	}
}

func TestFileWatcherReportsDependencyACLChange(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("uses macOS ACL commands")
	}
	account, err := user.Current()
	require.NoError(t, err)
	for _, right := range []string{"read", "search"} {
		t.Run(right, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			require.NoError(t, err)
			path := filepath.Join(root, "base", "pod.yaml")
			write(t, path, "kind: Pod")
			watcher, err := newFileWatcher(root, FileWatcherOptions{})
			require.NoError(t, err)
			discardDeliveries(t, watcher)
			selected := path
			if right == "search" {
				selected = filepath.Dir(path)
				info, err := os.Stat(selected)
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, os.Chmod(selected, info.Mode().Perm())) })
				require.NoError(t, os.Chmod(selected, 0o100))
			}
			plan := make(dependencyDirectories)
			plan.addPath(selected)
			require.True(t, watcher.syncDependencies(plan, true))

			before, err := os.Stat(selected)
			require.NoError(t, err)
			acl := "user:" + account.Username + " deny " + right
			output, err := exec.Command("/bin/chmod", "+a", acl, selected).CombinedOutput()
			if err != nil {
				t.Skipf("cannot set ACL: %v (%s)", err, output)
			}
			t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-N", selected).Run() })
			_, err = os.ReadFile(path)
			if err == nil {
				t.Skip("current user still has read access")
			}
			require.ErrorIs(t, err, fs.ErrPermission)
			after, err := os.Stat(selected)
			require.NoError(t, err)
			require.Equal(t, before.Mode(), after.Mode())

			event := fsnotify.Event{Name: selected, Op: fsnotify.Chmod}
			require.NoError(t, watcher.handle(event))
			require.Len(t, watcher.changes, 1)
			<-watcher.changes
			require.NoError(t, exec.Command("/bin/chmod", "-N", selected).Run())
			_, err = os.ReadFile(path)
			require.NoError(t, err)
			require.NoError(t, watcher.handle(event))
			require.Len(t, watcher.changes, 1)
		})
	}
}

func TestFileWatcherRereadsWhenDependencyPermissionChangesBeforeSync(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	file := filepath.Join(root, "pod.yaml")
	write(t, file, "kind: Pod")
	watcher, err := newFileWatcher(root, FileWatcherOptions{})
	require.NoError(t, err)
	discardDeliveries(t, watcher)
	plan := make(dependencyDirectories)
	plan.addPath(file)

	require.NoError(t, watcher.handle(fsnotify.Event{Name: file, Op: fsnotify.Chmod}))
	require.Empty(t, watcher.changes, "the primary watch ignores permission-only changes")
	require.True(t, watcher.syncDependencies(plan, true), "the new dependency needs a reread")
}

func TestFileWatcherRereadsWhenExcludedDependencyDirectoryAppears(t *testing.T) {
	for _, tc := range []struct {
		name       string
		excludeDir bool
	}{
		{name: "excluded directory", excludeDir: true},
		{name: "excluded manifests"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			require.NoError(t, err)
			late := filepath.Join(root, "base.yaml")
			watcher, err := newFileWatcher(root, FileWatcherOptions{
				Exclude: func(path string, isDir bool) bool {
					if isDir {
						return tc.excludeDir && path == late
					}
					return filepath.Dir(path) == late
				},
			})
			require.NoError(t, err)
			discardDeliveries(t, watcher)
			plan := make(dependencyDirectories)
			plan.addPath(late)

			write(t, filepath.Join(late, "kustomization.yaml"), "resources: [pod.yaml]")
			write(t, filepath.Join(late, "pod.yaml"), "kind: Pod")
			require.NoError(t, watcher.handle(fsnotify.Event{Name: late, Op: fsnotify.Create}))
			require.NoError(t, watcher.settled())
			_, registered := watcher.dirs[late]
			require.Equal(t, !tc.excludeDir, registered)
			require.Empty(t, watcher.changes, "the primary watch found no scannable files")
			require.True(t, watcher.syncDependencies(plan, true), "the new dependency needs a reread")
		})
	}
}

func TestFileWatcherSelectsHelmIgnoreTargetAndGitAssets(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	chart := filepath.Join(dir, "chart")
	git := filepath.Join(chart, ".git")
	write(t, filepath.Join(git, "settings"), "chart data")
	plan := make(dependencyDirectories)
	plan.addChart(t.Context(), chart, make(map[string]struct{}))
	require.True(t, plan[git].chart, "Helm can read included .git assets")

	rules := filepath.Join(dir, "config", "ignore-rules")
	write(t, rules, "/.helmignore\n.git/\n")
	err = os.Symlink(rules, filepath.Join(chart, ".helmignore"))
	if err != nil && runtime.GOOS == "windows" {
		t.Skipf("file symlink unavailable: %v", err)
	}
	require.NoError(t, err)
	plan = make(dependencyDirectories)
	plan.addChart(t.Context(), chart, make(map[string]struct{}))
	require.True(t, plan[filepath.Dir(rules)].matches(filepath.Base(rules)), "watch the symlinked rule file")
	require.NotContains(t, plan, git, "Helm ignore still excludes .git when configured")
}

func TestFileWatcherSelectsHelmIgnoreThroughSymlinkParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires filesystem resolution of a relative symlink target containing ..")
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	chart, config := filepath.Join(dir, "chart"), filepath.Join(dir, "config")
	sub := filepath.Join(config, "sub")
	jump, rules := filepath.Join(chart, "jump"), filepath.Join(config, "ignore-rules")
	write(t, filepath.Join(chart, "Chart.yaml"), "apiVersion: v2\nname: demo\nversion: 1.2.3\n")
	require.NoError(t, os.MkdirAll(sub, 0o750))
	require.NoError(t, os.Symlink(sub, jump))
	require.NoError(t, os.Symlink("jump/../ignore-rules", filepath.Join(chart, ".helmignore")))

	plan := make(dependencyDirectories)
	plan.addChart(t.Context(), chart, make(map[string]struct{}))
	require.True(t, plan[config].matches(filepath.Base(rules)), "watch for creation of the missing rule file")

	write(t, rules, "/.helmignore\n/jump/\n")
	_, err = loader.LoadDir(chart)
	require.NoError(t, err)
	plan = make(dependencyDirectories)
	plan.addChart(t.Context(), chart, make(map[string]struct{}))
	require.True(t, plan[config].matches(filepath.Base(rules)), "watch the rule file Helm opens")
	require.Equal(t, sub, plan[chart].links[filepath.Base(jump)], "watch for the intermediate link being retargeted")
}
