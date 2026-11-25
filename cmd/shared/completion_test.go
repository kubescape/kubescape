package shared

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestCompleteValues(t *testing.T) {
	fn := CompleteValues([]string{"low", "medium", "high", "critical"})

	got, directive := fn(nil, nil, "H")
	assert.Equal(t, []string{"High"}, got)
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)

	gotAll, directiveAll := fn(nil, nil, "")
	assert.Equal(t, []string{"low", "medium", "high", "critical"}, gotAll)
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directiveAll)

	gotNone, _ := fn(nil, nil, "unknown")
	assert.Empty(t, gotNone)
}
