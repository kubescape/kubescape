package cautils

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gitv5 "github.com/go-git/go-git/v5"
	configv5 "github.com/go-git/go-git/v5/config"
	plumbingv5 "github.com/go-git/go-git/v5/plumbing"
	objectv5 "github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

var TEST_REPOS = [...]string{"localrepo", "withoutremotes"}

type LocalGitRepositoryTestSuite struct {
	suite.Suite
	archives           map[string]*zip.ReadCloser
	gitRepositoryPaths map[string]string
	destinationPath    string
}

func unzipFile(zipPath, destinationFolder string) (*zip.ReadCloser, error) {
	archive, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, err
	}

	for _, f := range archive.File {
		filePath := filepath.Join(destinationFolder, f.Name) //nolint:gosec
		if !strings.HasPrefix(filePath, filepath.Clean(destinationFolder)+string(os.PathSeparator)) {
			return nil, fmt.Errorf("invalid file path")
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(filePath, os.ModePerm)
			continue
		}

		if erc := copyFileInFolder(filePath, f); erc != nil {
			return nil, erc
		}
	}

	return archive, err
}

func copyFileInFolder(filePath string, f *zip.File) (err error) {
	if err = os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
		return err
	}

	dstFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
	if err != nil {
		return err
	}
	defer func() {
		_ = dstFile.Close()
	}()

	fileInArchive, err := f.Open()
	if err != nil {
		return err
	}
	defer func() {
		_ = fileInArchive.Close()
	}()

	_, err = io.Copy(dstFile, fileInArchive) //nolint:gosec

	if err = dstFile.Close(); err != nil {
		return err
	}

	if err = fileInArchive.Close(); err != nil {
		return err
	}

	return err
}

func (s *LocalGitRepositoryTestSuite) SetupSuite() {
	s.archives = make(map[string]*zip.ReadCloser)
	s.gitRepositoryPaths = make(map[string]string)

	destinationPath := filepath.Join(".", "testdata", "temp")
	s.destinationPath = destinationPath
	os.RemoveAll(destinationPath)
	for _, repo := range TEST_REPOS {
		zippedFixturePath := filepath.Join(".", "testdata", repo+".git")
		gitRepositoryPath := filepath.Join(destinationPath, repo)
		archive, err := unzipFile(zippedFixturePath, destinationPath)

		if err == nil {
			s.archives[repo] = archive
			s.gitRepositoryPaths[repo] = gitRepositoryPath
		}
	}
}

func TestLocalGitRepositoryTestSuite(t *testing.T) {
	suite.Run(t, new(LocalGitRepositoryTestSuite))
}

func (s *LocalGitRepositoryTestSuite) TearDownSuite() {
	if s.archives != nil {
		for _, archive := range s.archives {
			if archive != nil {
				archive.Close()
			}
		}
	}

	os.RemoveAll(s.destinationPath)
}

func (s *LocalGitRepositoryTestSuite) TestInvalidRepositoryPath() {
	if _, err := NewLocalGitRepository("/invalidpath"); s.Error(err) {
		s.Equal("repository does not exist", err.Error())
	}
}

func (s *LocalGitRepositoryTestSuite) TestRepositoryWithoutRemotes() {
	if _, err := NewLocalGitRepository(s.gitRepositoryPaths["withoutremotes"]); s.Error(err) {
		s.Equal("no remotes found", err.Error())
	}
}

// TestGetGitRootDirWithoutUsableMetadata verifies that the repository root resolves from any path inside the worktree even when the branch and remote metadata NewLocalGitRepository demands is missing, otherwise scans of a subdirectory report paths relative to the scan directory instead of the repository root. See #2594.
func (s *LocalGitRepositoryTestSuite) TestGetGitRootDirWithoutUsableMetadata() {
	repoPath := s.gitRepositoryPaths["withoutremotes"]
	absRepoPath, err := filepath.Abs(repoPath)
	s.NoError(err)

	subDir := filepath.Join(repoPath, "workloads", "apps")
	s.NoError(os.MkdirAll(subDir, 0o750))
	defer os.RemoveAll(filepath.Join(repoPath, "workloads"))

	_, err = NewLocalGitRepository(subDir)
	s.Error(err, "the fixture must keep its metadata unusable for this test to mean anything")

	root, ok := GetGitRootDir(subDir)
	if s.True(ok) {
		s.Equal(absRepoPath, root)
	}
}

// TestGetGitRootDirOutsideRepository verifies that a path outside any repository reports no root rather than an arbitrary one
func (s *LocalGitRepositoryTestSuite) TestGetGitRootDirOutsideRepository() {
	_, ok := GetGitRootDir(s.T().TempDir())
	s.False(ok)
}

func (s *LocalGitRepositoryTestSuite) TestGetBranchName() {
	if localRepo, err := NewLocalGitRepository(s.gitRepositoryPaths["localrepo"]); s.NoError(err) {
		s.Equal("master", localRepo.GetBranchName())
	}
}

func (s *LocalGitRepositoryTestSuite) TestGetName() {
	if localRepo, err := NewLocalGitRepository(s.gitRepositoryPaths["localrepo"]); s.NoError(err) {
		if name, err := localRepo.GetName(); s.NoError(err) {
			s.Equal("localrepo", name)
		}

	}
}

func (s *LocalGitRepositoryTestSuite) TestGetOriginUrl() {
	if localRepo, err := NewLocalGitRepository(s.gitRepositoryPaths["localrepo"]); s.NoError(err) {
		if url, err := localRepo.GetRemoteUrl(); s.NoError(err) {
			s.Equal("git@github.com:testuser/localrepo", url)
		}
	}
}

func TestGetRemoteUrl(t *testing.T) {
	testCases := []struct {
		Name      string
		LocalRepo LocalGitRepository
		Want      string
		WantErr   error
	}{
		{
			Name: "Branch with missing upstream and missing 'origin' fallback should return an error",
			LocalRepo: LocalGitRepository{
				config: &configv5.Config{
					Branches: make(map[string]*configv5.Branch),
					Remotes:  make(map[string]*configv5.RemoteConfig),
				},
				head: plumbingv5.NewReferenceFromStrings("HEAD", "ref: refs/heads/v4"),
			},
			Want:    "",
			WantErr: fmt.Errorf("did not find a default remote with name 'origin'"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			localRepo := LocalGitRepository{
				config: &configv5.Config{
					Branches: make(map[string]*configv5.Branch),
					Remotes:  make(map[string]*configv5.RemoteConfig),
				},
				head: plumbingv5.NewReferenceFromStrings("HEAD", "ref: refs/heads/v4"),
			}

			want := tc.Want
			wantErr := tc.WantErr
			got, gotErr := localRepo.GetRemoteUrl()

			if got != want {
				t.Errorf("Remote URLs don’t match: got '%s', want '%s'", got, want)
			}

			if gotErr.Error() != wantErr.Error() {
				t.Errorf("Errors don’t match: got '%v', want '%v'", gotErr, wantErr)
			}
		},
		)
	}
}

func TestLocalGitRepositoryDetachedHead(t *testing.T) {
	fixture := createDetachedRepositoryFixture(t, "origin", "https://github.com/kubescape/detached-head-fixture.git")

	repository, err := NewLocalGitRepository(filepath.Join(fixture.root, "nested"))
	require.NoError(t, err)
	assert.Empty(t, repository.GetBranchName(), "a detached commit must not be reported as a branch")

	remoteURL, err := repository.GetRemoteUrl()
	require.NoError(t, err)
	assert.Equal(t, "https://github.com/kubescape/detached-head-fixture.git", remoteURL)
	name, err := repository.GetName()
	require.NoError(t, err)
	assert.Equal(t, "detached-head-fixture", name)

	root, err := repository.GetRootDir()
	require.NoError(t, err)
	wantRoot, err := filepath.EvalSymlinks(fixture.root)
	require.NoError(t, err)
	assert.Equal(t, wantRoot, root)

	commit, err := repository.GetLastCommit()
	require.NoError(t, err)
	assert.Equal(t, fixture.commit.String(), commit.SHA)
	assert.Equal(t, "fixture commit", commit.Message)
	assert.Equal(t, "Fixture Author", commit.Author.Name)
	assert.Equal(t, "Fixture Committer", commit.Committer.Name)
	assert.True(t, fixture.when.Equal(commit.Committer.Date))
}

func TestDetachedHeadRemoteResolution(t *testing.T) {
	tests := []struct {
		name       string
		remoteName string
		wantURL    string
		wantError  string
	}{
		{
			name:       "origin is the detached default",
			remoteName: "origin",
			wantURL:    "https://example.com/team/project.git",
		},
		{
			name:       "a non-origin remote is not guessed",
			remoteName: "upstream",
			wantError:  "did not find a default remote with name 'origin'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := createDetachedRepositoryFixture(t, tt.remoteName, "https://example.com/team/project.git")
			repository, err := NewLocalGitRepository(fixture.root)
			require.NoError(t, err)

			got, err := repository.GetRemoteUrl()
			if tt.wantError != "" {
				require.EqualError(t, err, tt.wantError)
				assert.Empty(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantURL, got)
		})
	}
}

func TestMetadataGitLocalDetachedHead(t *testing.T) {
	t.Run("origin produces complete detached metadata", func(t *testing.T) {
		fixture := createDetachedRepositoryFixture(t, "origin", "https://github.com/kubescape/detached-head-fixture.git")

		metadata, err := metadataGitLocal(fixture.root)
		require.NoError(t, err)
		require.NotNil(t, metadata)
		assert.Equal(t, "none", metadata.Branch)
		assert.Equal(t, "none", metadata.DefaultBranch)
		assert.Equal(t, "github", metadata.Provider)
		assert.Equal(t, "kubescape", metadata.Owner)
		assert.Equal(t, "detached-head-fixture", metadata.Repo)
		assert.Equal(t, "https://github.com/kubescape/detached-head-fixture", metadata.RemoteURL)
		wantRoot, rootErr := filepath.EvalSymlinks(fixture.root)
		require.NoError(t, rootErr)
		assert.Equal(t, wantRoot, metadata.LocalRootPath)
		assert.Equal(t, fixture.commit.String(), metadata.LastCommit.Hash)
		assert.Equal(t, "Fixture Committer", metadata.LastCommit.CommitterName)
		assert.True(t, fixture.when.Equal(metadata.LastCommit.Date))
	})

	t.Run("remote lookup failure preserves safe partial metadata", func(t *testing.T) {
		fixture := createDetachedRepositoryFixture(t, "upstream", "https://example.com/team/project.git")

		metadata, err := metadataGitLocal(fixture.root)
		require.EqualError(t, err, "did not find a default remote with name 'origin'")
		require.NotNil(t, metadata)
		assert.Equal(t, "none", metadata.Branch)
		assert.Equal(t, "none", metadata.DefaultBranch)
		wantRoot, rootErr := filepath.EvalSymlinks(fixture.root)
		require.NoError(t, rootErr)
		assert.Equal(t, wantRoot, metadata.LocalRootPath)
	})
}

type detachedRepositoryFixture struct {
	root   string
	commit plumbingv5.Hash
	when   time.Time
}

func createDetachedRepositoryFixture(t *testing.T, remoteName, remoteURL string) detachedRepositoryFixture {
	t.Helper()

	root := t.TempDir()
	repository, err := gitv5.PlainInit(root, false)
	require.NoError(t, err)
	worktree, err := repository.Worktree()
	require.NoError(t, err)
	require.NoError(t, os.Mkdir(filepath.Join(root, "nested"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(root, "README.md"), []byte("fixture\n"), 0o600))
	_, err = worktree.Add("README.md")
	require.NoError(t, err)

	when := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	commit, err := worktree.Commit("fixture commit", &gitv5.CommitOptions{
		Author: &objectv5.Signature{
			Name:  "Fixture Author",
			Email: "author@example.com",
			When:  when.Add(-time.Minute),
		},
		Committer: &objectv5.Signature{
			Name:  "Fixture Committer",
			Email: "committer@example.com",
			When:  when,
		},
	})
	require.NoError(t, err)
	_, err = repository.CreateRemote(&configv5.RemoteConfig{Name: remoteName, URLs: []string{remoteURL}})
	require.NoError(t, err)
	require.NoError(t, repository.Storer.SetReference(plumbingv5.NewHashReference(plumbingv5.HEAD, commit)))

	return detachedRepositoryFixture{root: root, commit: commit, when: when}
}
