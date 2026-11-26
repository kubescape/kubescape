package watch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/kubescape/kubescape/v4/core/pkg/filesizelimit"
	"helm.sh/helm/v3/pkg/ignore"
)

var (
	errHelmIgnoreNotRegular = errors.New(".helmignore is not a regular file")
	errHelmIgnoreTooLarge   = errors.New(".helmignore exceeds maximum size limit")
)

type dependencyDirectory struct {
	names       map[string]string
	links       map[string]string
	chart       bool
	permissions map[string]dependencyPermissions // active selections keyed by entry name
}

type dependencyPermissions struct {
	mode       fs.FileMode
	readable   bool
	searchable bool
}

func (d dependencyDirectory) matches(name string) bool {
	_, exact := d.names[strings.ToLower(name)]
	return exact || d.chart
}

// permissionsChanged distinguishes access changes from attribute events caused
// by a read. An ACL can change read access while leaving the mode unchanged.
func (d *dependencyDirectory) permissionsChanged(path string) bool {
	name := filepath.Base(path)
	previous, known := d.permissions[name]
	info, err := os.Stat(path)
	if err != nil {
		delete(d.permissions, name)
		return known
	}
	if d.permissions == nil {
		d.permissions = make(map[string]dependencyPermissions)
	}
	readable, searchable := dependencyAccess(path, info.IsDir())
	current := dependencyPermissions{mode: info.Mode(), readable: readable, searchable: searchable}
	d.permissions[name] = current
	return !known || current != previous
}

type dependencyDirectories map[string]dependencyDirectory

func (d dependencyDirectories) merge(dir string, selection dependencyDirectory) {
	current, ok := d[dir]
	if !ok {
		d[dir] = selection
		return
	}
	selection.chart = selection.chart || current.chart
	if len(current.names) > 0 {
		names := maps.Clone(current.names)
		maps.Copy(names, selection.names)
		selection.names = names
	}
	if len(current.links) > 0 {
		links := maps.Clone(current.links)
		maps.Copy(links, selection.links)
		selection.links = links
	}
	d[dir] = selection
}

type dependencyUpdate struct {
	dirs  dependencyDirectories
	added chan bool
}

// ReplaceRenderDependencies updates the watches for local files and Helm
// chart trees consulted by the latest render. It reports any new coverage.
func ReplaceRenderDependencies(ctx context.Context, watchers []*FileWatcher, files, charts map[string]struct{}) (bool, error) {
	dirs := make(dependencyDirectories)
	for path := range files {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		dirs.addPath(path)
	}
	visitedCharts := make(map[string]struct{})
	for chart := range charts {
		dirs.addChart(ctx, chart, visitedCharts)
		if err := ctx.Err(); err != nil {
			return false, err
		}
	}

	type scope struct{ root, resolved string }
	scopes := make([]scope, len(watchers))
	plans := make([]dependencyDirectories, len(watchers))
	var roots []string
	for i, w := range watchers {
		root := w.root
		if w.file != "" {
			root = w.dir
		}
		resolved, err := filepath.EvalSymlinks(root)
		if err != nil {
			resolved = root
		}
		scopes[i] = scope{root, resolved}
		roots = append(roots, resolved)
		plans[i] = make(dependencyDirectories)
	}
	dirs.addAncestors(roots)
	for dir, selection := range dirs {
		for i, s := range scopes {
			if relative, ok := relativeWithin(s.resolved, dir); ok {
				plans[i].merge(filepath.Join(s.root, relative), selection)
				break
			}
			if i == len(scopes)-1 {
				plans[0].merge(dir, selection)
			}
		}
	}

	added := false
	for i, w := range watchers {
		result := make(chan bool, 1)
		select {
		case w.dependencyUpdates <- dependencyUpdate{plans[i], result}:
		case <-ctx.Done():
			return false, ctx.Err()
		case <-w.done:
			if err := w.Err(); err != nil {
				return false, err
			}
			return false, context.Canceled
		}
		select {
		case changed := <-result:
			added = added || changed
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	return added, nil
}

func relativeWithin(root, path string) (string, bool) {
	rel, err := filepath.Rel(root, path)
	return rel, err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func (d dependencyDirectories) addPath(path string) {
	d.addEntry(path)
	if resolved, err := filepath.EvalSymlinks(path); err == nil && path == resolved {
		return
	}
	d.addLinks(path, make(map[string]struct{}))
}

// Link changes are reported beside the link. Record the link entries the
// requested name traverses, including links named by other links.
func (d dependencyDirectories) addLinks(path string, seen map[string]struct{}) {
	for dir, name := splitDependencyPath(path); name != "" && len(seen) < 255; dir, name = splitDependencyPath(dir) {
		target, err := os.Readlink(dir + name)
		if err != nil {
			continue
		}
		parent, err := filepath.EvalSymlinks(dir)
		if err != nil {
			continue
		}
		physicalLink := filepath.Join(parent, name)
		if _, ok := seen[physicalLink]; ok {
			continue
		}
		seen[physicalLink] = struct{}{}
		d.addName(parent, name)
		selection := d[parent]
		if selection.links == nil {
			selection.links = make(map[string]string)
		}
		selection.links[name] = target
		d[parent] = selection
		if !filepath.IsAbs(target) {
			// Resolve the link target before interpreting any parent segments.
			target = strings.TrimSuffix(parent, string(filepath.Separator)) + string(filepath.Separator) + target
		}
		d.addEntry(target)
		d.addLinks(target, seen)
	}
}

// A watch on a descendant can stay attached to the old inode when a higher
// directory moves. Watch the directory entries back to the scan's tree.
func (d dependencyDirectories) addAncestors(roots []string) {
	seen := make(map[string]struct{}, len(d))
	for _, root := range roots {
		seen[root] = struct{}{}
	}
	for dir := range maps.Clone(d) {
		for name := dir; filepath.Dir(name) != name; name = filepath.Dir(name) {
			if _, ok := seen[name]; ok {
				break
			}
			seen[name] = struct{}{}
			parent := filepath.Dir(name)
			d.addName(parent, filepath.Base(name))
			if containsInputRoot(parent, roots) {
				break
			}
		}
	}
}

func containsInputRoot(dir string, roots []string) bool {
	for _, root := range roots {
		if _, ok := relativeWithin(dir, root); ok {
			return true
		}
	}
	return false
}

// splitDependencyPath preserves parent segments so each symlink is followed
// before any ".." that comes after it.
func splitDependencyPath(path string) (dir, name string) {
	return filepath.Split(strings.TrimRightFunc(path, func(r rune) bool {
		return r == '/' || r == filepath.Separator
	}))
}

func (d dependencyDirectories) addEntry(path string) {
	for dir, name := splitDependencyPath(path); name != ""; dir, name = splitDependencyPath(dir) {
		parent, err := filepath.EvalSymlinks(dir)
		if err != nil {
			continue
		}
		if info, err := os.Stat(parent); err != nil || !info.IsDir() {
			continue
		}
		entry := filepath.Join(parent, name)
		if entryDir := filepath.Dir(entry); entryDir != entry {
			d.addName(entryDir, filepath.Base(entry))
		}
		break
	}
}

func (d dependencyDirectories) addName(parent, name string) {
	selection := d[parent]
	if selection.names == nil {
		selection.names = make(map[string]string)
	}
	// Case-insensitive filesystems report the spelling in the directory.
	selection.names[strings.ToLower(name)] = name
	d[parent] = selection
}

func (d dependencyDirectories) addChart(ctx context.Context, chart string, visited map[string]struct{}) {
	d.addPath(chart)
	root, err := filepath.EvalSymlinks(chart)
	if err != nil {
		return
	}
	if _, ok := visited[root]; ok {
		return
	}
	visited[root] = struct{}{}
	rules := ignore.Empty()
	ignorePath := filepath.Join(root, ignore.HelmIgnore)
	d.addPath(ignorePath) // Helm reads the rules before applying them to chart entries.
	if parsed, err := loadHelmIgnoreRules(ignorePath); err == nil {
		rules = parsed
	}
	rules.AddDefaults()
	d.addChartDirectory(ctx, root, "", rules, make(map[string]struct{}))
}

// openRegularHelmIgnoreFile opens path with O_NONBLOCK and validates both
// before opening and on the opened descriptor that it refers to a regular file.
func openRegularHelmIgnoreFile(path string) (*os.File, fs.FileInfo, error) {
	cleaned := filepath.Clean(path)
	statInfo, err := os.Stat(cleaned)
	if err != nil {
		return nil, nil, err
	}
	if statInfo.IsDir() {
		return nil, nil, fmt.Errorf("%q is a directory, not a file: %w", path, errHelmIgnoreNotRegular)
	}
	if !statInfo.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%w: %q", errHelmIgnoreNotRegular, path)
	}

	file, err := os.OpenFile(cleaned, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if info.IsDir() {
		_ = file.Close()
		return nil, nil, fmt.Errorf("%q is a directory, not a file: %w", path, errHelmIgnoreNotRegular)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, fmt.Errorf("%w: %q", errHelmIgnoreNotRegular, path)
	}
	return file, info, nil
}

// loadHelmIgnoreRules reads and parses a .helmignore file without blocking on
// non-regular files and bounds reads by filesizelimit.GetMaxFileSize().
func loadHelmIgnoreRules(path string) (*ignore.Rules, error) {
	file, info, err := openRegularHelmIgnoreFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	limit := filesizelimit.GetMaxFileSize()
	if info.Size() > limit {
		return nil, fmt.Errorf("%w: %q exceeds the %d byte limit", errHelmIgnoreTooLarge, path, limit)
	}

	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: %q exceeds the %d byte limit", errHelmIgnoreTooLarge, path, limit)
	}

	return ignore.Parse(bytes.NewReader(data))
}

func (d dependencyDirectories) addChartDirectory(ctx context.Context, dir, relative string, rules *ignore.Rules, stack map[string]struct{}) {
	if _, cyclic := stack[dir]; cyclic || ctx.Err() != nil {
		return
	}
	stack[dir] = struct{}{}
	defer delete(stack, dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	selection := d[dir]
	selection.chart = true
	d[dir] = selection
	for _, entry := range entries {
		if ctx.Err() != nil {
			return
		}
		path := filepath.Join(dir, entry.Name())
		child := filepath.Join(relative, entry.Name())
		link := entry.Type()&fs.ModeSymlink != 0
		info, err := os.Stat(path)
		if err != nil {
			if link {
				// Creating the target can repair a failed Helm render.
				d.addPath(path)
			}
			continue
		}
		if rules.Ignore(filepath.ToSlash(child), info) {
			continue
		}
		if link {
			d.addPath(path)
			if path, err = filepath.EvalSymlinks(path); err != nil {
				continue
			}
			if !info.IsDir() {
				d.addEntry(path)
			}
		}
		if info.IsDir() {
			d.addChartDirectory(ctx, path, child, rules, stack)
		}
	}
}

// syncDependencies runs on the watcher goroutine, sharing directories with
// the regular watch and retrying optional registrations without stopping it.
func (w *FileWatcher) syncDependencies(plan dependencyDirectories, report bool) bool {
	w.dependencyPlan = plan
	w.dependencyRetry = nil
	if len(plan) == 0 && len(w.dependencyDirs) == 0 {
		return false
	}
	aliases := make(map[string]string, len(w.dirs)+len(w.dependencyDirs))
	for dir := range w.dependencyDirs {
		aliases[strings.ToLower(dir)] = dir
	}
	for dir := range w.dirs {
		aliases[strings.ToLower(dir)] = dir
	}
	normalized := make(dependencyDirectories, len(plan))
	for dir, selection := range plan {
		key := strings.ToLower(dir)
		if alias := aliases[key]; alias != "" && alias != dir && sameDirectory(dir, alias) {
			dir = alias
		}
		aliases[key] = dir
		normalized.merge(dir, selection)
	}
	active := make(dependencyDirectories, len(plan))
	added := false
	for dir, selection := range normalized {
		_, primary := w.dirs[dir]
		previous, already := w.dependencyDirs[dir]
		if !primary && !already {
			if err := w.addDirectoryWatch(dir); err != nil {
				if report {
					if errors.Is(err, fs.ErrNotExist) {
						// Replan from the original paths if a parent disappeared
						// between discovery and registration.
						added = true
					} else {
						w.report(limitError(dir, err))
					}
				}
				if w.dependencyRetry == nil {
					w.dependencyRetry = time.After(time.Second)
				}
				continue
			}
		}
		if (selection.chart && !previous.chart) || (!primary && !already) {
			added = true
		}
		selection.permissions = previous.permissions
		for name := range selection.permissions {
			if !selection.matches(name) {
				delete(selection.permissions, name)
			}
		}
		for _, name := range selection.names {
			// Primary watches may have filtered a change before a name was selected.
			if !previous.matches(name) {
				added = true
			}
			if _, known := selection.permissions[name]; !known {
				selection.permissionsChanged(filepath.Join(dir, name))
			}
		}
		active[dir] = selection
	}
	for dir := range w.dependencyDirs {
		if _, keep := active[dir]; !keep {
			if _, primary := w.dirs[dir]; !primary {
				_ = w.fs.Remove(dir)
			}
		}
	}
	w.dependencyDirs = active
	return added
}

// kqueue observes the link target and can miss an atomic replacement of the
// link itself. Check just the links consulted during the render.
func (w *FileWatcher) watchDependencyLinks(plan dependencyDirectories) bool {
	previous := w.dependencyLinks
	w.dependencyLinks = make(map[string]string)
	w.dependencyLinkCheck = nil
	changed := false
	for dir, selection := range plan {
		for name, target := range selection.links {
			path := filepath.Join(dir, name)
			oldTarget, known := previous[path]
			changed = changed || !known || oldTarget != target
			w.dependencyLinks[path] = target
		}
	}
	for path, oldTarget := range previous {
		if _, recorded := w.dependencyLinks[path]; !recorded &&
			plan[filepath.Dir(path)].matches(filepath.Base(path)) {
			// kqueue can miss the same-name recreation of a missing link.
			w.dependencyLinks[path] = ""
			changed = changed || oldTarget != ""
		}
	}
	if len(w.dependencyLinks) > 0 {
		w.dependencyLinkCheck = time.After(time.Second)
	}
	// Planning samples after the render. A new or changed link requires a
	// reread even if both target directories were already watched.
	return changed || len(w.dependencyLinks) < len(previous)
}

func (w *FileWatcher) checkDependencyLinks() {
	for path, previous := range w.dependencyLinks {
		target, _ := os.Readlink(path)
		if target != previous {
			w.dependencyLinks[path] = target
			w.notify(path)
		}
	}
	w.dependencyLinkCheck = time.After(time.Second)
}

func sameDirectory(left, right string) bool {
	a, err := os.Stat(left)
	if err != nil {
		return false
	}
	b, err := os.Stat(right)
	return err == nil && os.SameFile(a, b)
}

func (w *FileWatcher) dependencyEvent(path string, event fsnotify.Event) bool {
	dir, name := filepath.Dir(path), filepath.Base(path)
	selection := w.dependencyDirs[dir]
	if !selection.matches(name) {
		return false
	}
	if event.Has(fsnotify.Create | fsnotify.Remove | fsnotify.Rename) {
		delete(selection.permissions, name)
		return true
	}
	if event.Has(fsnotify.Chmod) {
		changed := selection.permissionsChanged(path)
		w.dependencyDirs[dir] = selection
		if changed || event.Op == fsnotify.Chmod {
			return changed
		}
	}
	info, err := os.Lstat(path)
	return err != nil || !info.IsDir() // some backends report writes to the containing directory
}
