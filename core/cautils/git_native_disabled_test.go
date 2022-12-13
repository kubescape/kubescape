//go:build !gitenabled

package cautils

func (s *LocalGitRepositoryTestSuite) TestGetLastCommit() {
	s.T().Log("warn: skipped testsing native git functionality [GetLastCommit]")
}

func (s *LocalGitRepositoryTestSuite) TestGetFileLastCommit() {
	s.T().Log("warn: skipped testsing native git functionality [GetFileLastCommit]")
}
