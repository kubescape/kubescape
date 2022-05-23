package resourcehandler

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
)

type LocalGitRepositoryTestSuite struct {
	suite.Suite
	archive           *zip.ReadCloser
	gitRepositoryPath string
	destinationPath   string
}

func unzipFile(zipPath, destinationFolder string) (*zip.ReadCloser, error) {
	archive, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, err
	}
	for _, f := range archive.File {
		filePath := filepath.Join(destinationFolder, f.Name)
		if !strings.HasPrefix(filePath, filepath.Clean(destinationFolder)+string(os.PathSeparator)) {
			return nil, fmt.Errorf("invalid file path")
		}
		if f.FileInfo().IsDir() {
			os.MkdirAll(filePath, os.ModePerm)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
			return nil, err
		}

		dstFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return nil, err
		}

		fileInArchive, err := f.Open()
		if err != nil {
			return nil, err
		}

		if _, err := io.Copy(dstFile, fileInArchive); err != nil {
			return nil, err
		}

		dstFile.Close()
		fileInArchive.Close()
	}

	return archive, err

}

func (s *LocalGitRepositoryTestSuite) SetupSuite() {
	zippedFixturePath := path.Join(".", "testdata", "localrepo.git")
	destinationPath := path.Join(".", "testdata", "temp")
	gitRepositoryPath := path.Join(destinationPath, "localrepo")

	os.RemoveAll(destinationPath)
	archive, err := unzipFile(zippedFixturePath, destinationPath)

	if err == nil {
		s.archive = archive
		s.gitRepositoryPath = gitRepositoryPath
		s.destinationPath = destinationPath
	}
}

func TestLocalGitRepositoryTestSuite(t *testing.T) {
	suite.Run(t, new(LocalGitRepositoryTestSuite))
}

func (s *LocalGitRepositoryTestSuite) TearDownSuite() {
	if s.archive != nil {
		s.archive.Close()
	}
	os.RemoveAll(s.destinationPath)
}

func (s *LocalGitRepositoryTestSuite) TestInvalidRepositoryPath() {
	if _, err := NewLocalGitRepository("invalidpath"); s.Error(err) {
		s.Equal("repository does not exist", err.Error())
	}
}

func (s *LocalGitRepositoryTestSuite) TestGetBranchName() {
	if localRepo, err := NewLocalGitRepository(s.gitRepositoryPath); s.NoError(err) {
		s.Equal("master", localRepo.GetBranchName())
	}
}

func (s *LocalGitRepositoryTestSuite) TestGetName() {
	if localRepo, err := NewLocalGitRepository(s.gitRepositoryPath); s.NoError(err) {
		s.Equal("localrepo", localRepo.GetName())
	}
}

func (s *LocalGitRepositoryTestSuite) TestGetOriginUrl() {
	if localRepo, err := NewLocalGitRepository(s.gitRepositoryPath); s.NoError(err) {
		s.Equal("git@github.com:testuser/localrepo", localRepo.GetOriginUrl())
	}
}

func (s *LocalGitRepositoryTestSuite) TestGetLastCommit() {
	if localRepo, err := NewLocalGitRepository(s.gitRepositoryPath); s.NoError(err) {
		if commit, err := localRepo.GetLastCommit(); s.NoError(err) {
			s.Equal("7e09312b8017695fadcd606882e3779f10a5c832", commit.hash)
			s.Equal("Amir Malka", commit.authorName)
			s.Equal("amirm@armosec.io", commit.authorEmail)
			s.Equal("2022-05-22 19:11:57 +0300 +0300", commit.date)
			s.Equal("added file B\n", commit.message)
		}
	}
}

func (s *LocalGitRepositoryTestSuite) TestGetFileLastCommit() {
	s.Run("fileA", func() {
		if localRepo, err := NewLocalGitRepository(s.gitRepositoryPath); s.NoError(err) {
			if commit, err := localRepo.GetFileLastCommit("fileA"); s.NoError(err) {
				s.Equal("9fae4be19624297947d2b605cefbff516628612d", commit.hash)
				s.Equal("Amir Malka", commit.authorName)
				s.Equal("amirm@armosec.io", commit.authorEmail)
				s.Equal("2022-05-22 18:55:48 +0300 +0300", commit.date)
				s.Equal("added file A\n", commit.message)
			}
		}
	})

	s.Run("fileB", func() {
		if localRepo, err := NewLocalGitRepository(s.gitRepositoryPath); s.NoError(err) {
			if commit, err := localRepo.GetFileLastCommit("dirA/fileB"); s.NoError(err) {
				s.Equal("7e09312b8017695fadcd606882e3779f10a5c832", commit.hash)
				s.Equal("Amir Malka", commit.authorName)
				s.Equal("amirm@armosec.io", commit.authorEmail)
				s.Equal("2022-05-22 19:11:57 +0300 +0300", commit.date)
				s.Equal("added file B\n", commit.message)
			}
		}
	})
}
