package getter

func MockNewLoadPolicy() *LoadPolicy {
	return &LoadPolicy{
		filePaths: []string{""},
	}
}
