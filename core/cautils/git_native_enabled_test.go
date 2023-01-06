//go:build gitenabled
package cautils

func (s *LocalGitRepositoryTestSuite) TestGetLastCommit() {
	if localRepo, err := NewLocalGitRepository(s.gitRepositoryPaths["localrepo"]); s.NoError(err) {
		if commit, err := localRepo.GetLastCommit(); s.NoError(err) {
			s.Equal("7e09312b8017695fadcd606882e3779f10a5c832", commit.SHA)
			s.Equal("Amir Malka", commit.Author.Name)
			s.Equal("amirm@armosec.io", commit.Author.Email)
			s.Equal("2022-05-22 19:11:57 +0300 +0300", commit.Author.Date.String())
			s.Equal("added file B\n", commit.Message)
		}
	}
}

func (s *LocalGitRepositoryTestSuite) TestGetFileLastCommit() {
	s.Run("fileA", func() {
		if localRepo, err := NewLocalGitRepository(s.gitRepositoryPaths["localrepo"]); s.NoError(err) {

			if commit, err := localRepo.GetFileLastCommit("fileA"); s.NoError(err) {
				s.Equal("9fae4be19624297947d2b605cefbff516628612d", commit.SHA)
				s.Equal("Amir Malka", commit.Author.Name)
				s.Equal("amirm@armosec.io", commit.Author.Email)
				s.Equal("2022-05-22 18:55:48 +0300 +0300", commit.Author.Date.String())
				s.Equal("added file A\n", commit.Message)
			}

		}
	})

	s.Run("fileB", func() {
		if localRepo, err := NewLocalGitRepository(s.gitRepositoryPaths["localrepo"]); s.NoError(err) {

			if commit, err := localRepo.GetFileLastCommit("dirA/fileB"); s.NoError(err) {
				s.Equal("7e09312b8017695fadcd606882e3779f10a5c832", commit.SHA)
				s.Equal("Amir Malka", commit.Author.Name)
				s.Equal("amirm@armosec.io", commit.Author.Email)
				s.Equal("2022-05-22 19:11:57 +0300 +0300", commit.Author.Date.String())
				s.Equal("added file B\n", commit.Message)
			}

		}
	})
}
