package getter

import "github.com/armosec/armoapi-go/armotypes"

var _ IExceptionsGetter = &MergedExceptionsGetter{}

// MergedExceptionsGetter combines exceptions from a primary source and a secondary source.
// Primary source failures are returned as errors; secondary source failures are ignored.
type MergedExceptionsGetter struct {
	primary   IExceptionsGetter
	secondary IExceptionsGetter
}

func NewMergedExceptionsGetter(primary, secondary IExceptionsGetter) *MergedExceptionsGetter {
	return &MergedExceptionsGetter{primary: primary, secondary: secondary}
}

func (g *MergedExceptionsGetter) GetExceptions(clusterName string) ([]armotypes.PostureExceptionPolicy, error) {
	if g == nil || g.primary == nil {
		return []armotypes.PostureExceptionPolicy{}, nil
	}

	exceptions, err := g.primary.GetExceptions(clusterName)
	if err != nil {
		return nil, err
	}

	if g.secondary == nil {
		return exceptions, nil
	}

	crdExceptions, err := g.secondary.GetExceptions(clusterName)
	if err != nil {
		return exceptions, nil
	}

	if len(crdExceptions) == 0 {
		return exceptions, nil
	}

	merged := make([]armotypes.PostureExceptionPolicy, 0, len(exceptions)+len(crdExceptions))
	merged = append(merged, exceptions...)
	merged = append(merged, crdExceptions...)
	return merged, nil
}
