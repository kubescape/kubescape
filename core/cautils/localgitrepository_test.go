package cautils

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	configv5 "github.com/go-git/go-git/v5/config"
	plumbingv5 "github.com/go-git/go-git/v5/plumbing"
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
