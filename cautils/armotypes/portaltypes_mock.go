package armotypes

func MockPortalBase(customerGUID, name string, attributes map[string]interface{}) *PortalBase {
	if customerGUID == "" {
		customerGUID = "36b6f9e1-3b63-4628-994d-cbe16f81e9c7"
	}
	if name == "" {
		name = "portalbase-a"
	}
	if attributes == nil {
		attributes = make(map[string]interface{})
	}
	return &PortalBase{
		GUID:       customerGUID,
		Name:       name,
		Attributes: attributes,
	}
}
