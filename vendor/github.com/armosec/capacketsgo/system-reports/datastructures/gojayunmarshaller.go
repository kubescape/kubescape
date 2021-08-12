package datastructures

import (
	"time"

	"github.com/francoispqt/gojay"
)

func (reporter *BaseReport) UnmarshalJSONObject(dec *gojay.Decoder, key string) (err error) {
	switch key {
	case "timestamp":
		err = dec.Time(&(reporter.Timestamp), time.RFC3339)
		reporter.Timestamp = reporter.Timestamp.Local()
	case "reporter":
		err = dec.String(&(reporter.Reporter))
	case "target":
		err = dec.String(&(reporter.Target))
	case "status":
		err = dec.String(&(reporter.Status))
	case "actionID":
		err = dec.String(&(reporter.ActionID))
	case "jobID":
		err = dec.String(&(reporter.JobID))
	case "action":
		err = dec.String(&(reporter.ActionName))
	case "parentAction":
		err = dec.String(&(reporter.ParentAction))
	case "numSeq":

		err = dec.Int(&(reporter.ActionIDN))

	case "errors":
		err = dec.SliceString(&(reporter.Errors))

	case "customerGUID":
		err = dec.String(&(reporter.CustomerGUID))
	}
	return err
}

// func (errors *[]string) UnmarshalJSONArray(dec *gojay.Decoder) error {
// 	lae := ""
// 	if err := dec.String(&lae); err != nil {
// 		return err
// 	}

// 	*t = append(*t, lae)
// 	return nil
// }

func (ae *BaseReport) NKeys() int {
	return 0
}
