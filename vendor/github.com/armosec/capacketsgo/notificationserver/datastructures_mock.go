package notificationserver

func MockNotificationA() *Notification {
	return &Notification{
		Target: map[string]string{
			TargetCluster:   "",
			TargetCustomer:  "",
			TargetComponent: TargetComponentPostureValue,
		},
		Notification: nil,
	}
}
