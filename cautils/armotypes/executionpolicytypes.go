package armotypes

type EnforcementsRule struct {
	MonitoredObject          []string `json:"monitoredObject"`
	MonitoredObjectExistence []string `json:"objectExistence"`
	MonitoredObjectEvent     []string `json:"event"`
	Action                   []string `json:"action"`
}

type ExecutionPolicy struct {
	PortalBase                `json:",inline"`
	Designators               []PortalDesignator `json:"designators"`
	PolicyType                string             `json:"policyType"`
	CreationTime              string             `json:"creation_time"`
	ExecutionEnforcementsRule []EnforcementsRule `json:"enforcementRules"`
}
