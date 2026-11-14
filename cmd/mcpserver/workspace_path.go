package mcpserver

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/kubescape/kubescape/v4/core/pkg/pathcontainment"
	"github.com/mark3labs/mcp-go/mcp"
)

var errWorkspaceFileTooLarge = errors.New("workspace file exceeds size limit")

// openWorkspaceRoot returns the server's startup-anchored workspace root. A
// server built directly by a test has no startup root, so it opens one for the
// duration of the call instead.
func (ksServer *KubescapeMcpserver) openWorkspaceRoot() (*os.Root, func(), error) {
	if ksServer.workspaceDir == "" {
		return nil, func() {}, nil
	}
	if ksServer.workspaceRoot != nil {
		return ksServer.workspaceRoot, func() {}, nil
	}
	root, err := os.OpenRoot(ksServer.workspaceDir)
	if err != nil {
		return nil, nil, err
	}
	return root, func() { _ = root.Close() }, nil
}

// openFileUnderRoot opens path relative to an already-open workspace root.
// Unlike a pathname preflight followed by os.Open, Root.OpenFile checks every
// component at the time of access and refuses symlink traversal outside root.
func openFileUnderRoot(root *os.Root, path string) (*os.File, error) {
	if root == nil {
		return nil, errors.New("workspace root is not open")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve path: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	rootPath, err := filepath.Abs(root.Name())
	if err != nil {
		return nil, fmt.Errorf("cannot resolve workspace root: %w", err)
	}
	rootPath, err = filepath.EvalSymlinks(rootPath)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve workspace root: %w", err)
	}
	rootStat, err := root.Stat(".")
	if err != nil {
		return nil, fmt.Errorf("cannot stat workspace root: %w", err)
	}
	rootPathStat, err := os.Stat(rootPath)
	if err != nil {
		return nil, fmt.Errorf("cannot stat resolved workspace root: %w", err)
	}
	if !os.SameFile(rootStat, rootPathStat) {
		return nil, fmt.Errorf("%w: workspace root %q no longer identifies opened directory", pathcontainment.ErrPathEscapesWorkspace, root.Name())
	}
	rel, err := filepath.Rel(rootPath, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return nil, fmt.Errorf("%w: %q", pathcontainment.ErrPathEscapesWorkspace, path)
	}
	f, err := root.OpenFile(rel, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("%q is not a regular file", path)
	}
	return f, nil
}

// readFileUnderRoot reads a regular file through root and bounds the read even
// if the file grows after its descriptor is opened.
func readFileUnderRoot(root *os.Root, path string, maxBytes int64) ([]byte, error) {
	f, err := openFileUnderRoot(root, path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("%w: %q is %d bytes, limit is %d", errWorkspaceFileTooLarge, path, info.Size(), maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%w: %q exceeds %d bytes", errWorkspaceFileTooLarge, path, maxBytes)
	}
	return data, nil
}

// containToWorkspace confines a file path a tool argument names to the
// --workspace root, as path already is for local IaC scans. Tools that read a
// report or the files a report names must honour the same boundary; otherwise
// a client confined to the workspace for scans could still have files outside
// it read and their contents returned.
//
// Without a workspace (unconstrained mode) or for an empty argument the value
// is returned unchanged, so the tool's own validation and messages apply as
// before. A relative path resolves against the workspace, as it does for path.
func (ksServer *KubescapeMcpserver) containToWorkspace(argument, value string) (string, *mcp.CallToolResult) {
	if ksServer.workspaceDir == "" || value == "" {
		return value, nil
	}
	resolved, err := pathcontainment.ResolveContainedPath(ksServer.workspaceDir, value)
	if err != nil {
		return "", mcpToolError(ErrCodeInvalidArgument,
			fmt.Sprintf("invalid or unauthorized path: %s: %v", argument, err),
			map[string]any{"argument": argument})
	}
	return resolved, nil
}
