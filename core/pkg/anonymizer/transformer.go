package anonymizer

type Transformer interface {
	Transform(prefix, value string) (string, error)
}
