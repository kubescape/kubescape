# Audit-logs connector
## Example
===
Define this *ELASTICSEARCH_URL*
Or use pre-defined elastic client by calling ReinitElastic function

```
AuditReportAction(&AuditReport{
		Source:   AuditSourceTest,
		Details:  "here is some test detail",
		Subject:  "the go compiler",
		Action:   "ran in test mode",
		User:     "ben",
		Customer: "35d5509a-e81a-492b-a4c6-55264de33e0b",
	})
```