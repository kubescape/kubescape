package lsp

// fakeWorkload is a resource whose path is "<file>:<document index>", as a local
// workload's is.
type fakeWorkload struct{ path string }

func (f fakeWorkload) GetPath() string { return f.path }
