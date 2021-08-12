package opapolicy

import (
	"github.com/francoispqt/gojay"
	"time"
)

/*
  responsible on fast unmarshaling of various COMMON containerscan structures and substructures

*/
// UnmarshalJSONObject - File inside a pkg
func (r *PostureReport) UnmarshalJSONObject(dec *gojay.Decoder, key string) (err error) {

	switch key {
	case "customerGUID":
		err = dec.String(&(r.CustomerGUID))

	case "clusterName":
		err = dec.String(&(r.ClusterName))

	case "reportID":
		err = dec.String(&(r.ReportID))
	case "jobID":
		err = dec.String(&(r.JobID))
	case "generationTime":
		err = dec.Time(&(r.ReportGenerationTime), time.RFC3339)
		r.ReportGenerationTime = r.ReportGenerationTime.Local()
	}
	return err

}

// func (files *PkgFiles) UnmarshalJSONArray(dec *gojay.Decoder) error {
// 	lae := PackageFile{}
// 	if err := dec.Object(&lae); err != nil {
// 		return err
// 	}

// 	*files = append(*files, lae)
// 	return nil
// }

func (file *PostureReport) NKeys() int {
	return 0
}
//------------------------
