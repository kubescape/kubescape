package anonymizer

type MappingTransformer struct {
	mapping *Mapping
}

func NewMappingTransformer() *MappingTransformer {
	return &MappingTransformer{
		mapping: NewMapping(),
	}
}

func (t *MappingTransformer) Transform(
	prefix string,
	value string,
) (string, error) {
	return t.mapping.GetOrCreate(prefix, value), nil
}
