package datastructures

//BaseReportMock : represents the basic reports from various actions eg. attach and so on
type BaseReportMock struct {
	BaseReport `json:",inline"`
}

// NewBaseReportMock -
func NewBaseReportMock(costumerGUID, reporter string) *BaseReportMock {
	brm := BaseReportMock{}
	brm.Reporter = reporter
	brm.CustomerGUID = costumerGUID
	brm.Status = "started"
	return &brm

}
