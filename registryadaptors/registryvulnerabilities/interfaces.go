package registryvulnerabilities

type IContainerImageVulnerabilityAdaptor interface {
	// Credentials are coming from user input (CLI or configuration file) and they are abstracted at string to string map level
	// so and example use would be like registry: "simpledockerregistry:80" and credentials like {"username":"joedoe","password":"abcd1234"}
	Login() error

	// For "help" purposes
	DescribeAdaptor() string

	GetImagesScanStatus(imageIDs []ContainerImageIdentifier) ([]ContainerImageScanStatus, error)

	GetImagesVulnerabilities(imageIDs []ContainerImageIdentifier) ([]ContainerImageVulnerabilityReport, error)
	GetImageVulnerability(imageID *ContainerImageIdentifier) (*ContainerImageVulnerabilityReport, error)

	GetImagesInformation(imageIDs []ContainerImageIdentifier) ([]ContainerImageInformation, error)
}
