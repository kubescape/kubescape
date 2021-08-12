package notificationserver

// Notification passed between servers
type Notification struct {
	Target            map[string]string `json:"target"`
	SendSynchronicity bool              `json:"sendSynchronicity"`
	Notification      interface{}       `json:"notification"`
}
