package fixhandler

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContentNewlinesMatchTarget(t *testing.T) {
	cases := []struct {
		Name          string
		InputContent  string
		TargetNewline string
		WantedContent string
	}{
		{
			"Unix to DOS",
			"first line\nsecond line\n",
			"\r\n",
			"first line\r\nsecond line\r\n",
		},
		{
			"Unix to Unix",
			"first line\nsecond line\n",
			"\n",
			"first line\nsecond line\n",
		},
		{
			"Unix to Mac",
			"first line\nsecond line\n",
			"\r",
			"first line\rsecond line\r",
		},
		{
			"DOS to Unix",
			"first line\r\nsecond line\r\n",
			"\n",
			"first line\nsecond line\n",
		},
		{
			"DOS to DOS",
			"first line\r\nsecond line\r\n",
			"\r\n",
			"first line\r\nsecond line\r\n",
		},
		{
			"DOS to OldMac",
			"first line\r\nsecond line\r\n",
			"\r",
			"first line\rsecond line\r",
		},
		{
			"Mac to DOS",
			"first line\rsecond line\r",
			"\r\n",
			"first line\r\nsecond line\r\n",
		},
		{
			"Mac to Unix",
			"first line\rsecond line\r",
			"\n",
			"first line\nsecond line\n",
		},
		{
			"DOS, Mac to Unix",
			"first line\r\n\rsecond line\r",
			"\n",
			"first line\n\nsecond line\n",
		},
		{
			"Mac, DOS to Unix",
			"first line\r\r\r\nsecond line\r",
			"\n",
			"first line\n\n\nsecond line\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			c := &contentToAdd{content: tc.InputContent}
			want := tc.WantedContent

			got := c.Content(tc.TargetNewline)

			assert.Equal(t, want, got)
		})
	}

}
