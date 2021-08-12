package auditconnector

import (
	"log"

	elasticsearch "github.com/elastic/go-elasticsearch/v7"
)

var elasticClient *elasticsearch.Client = nil

func init() {
	var err error
	elasticClient, err = elasticsearch.NewDefaultClient()
	if err != nil {
		log.Print(err)
		log.Print("Error: audit elasticsearch client could not be created")
		elasticClient = nil
	}
}

// ReinitElastic inits the underlying elastic client with well-configured one instead of the default one
func ReinitElastic(client *elasticsearch.Client) {
	if client != nil {
		elasticClient = client
	}
}
