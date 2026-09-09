package fixhandler

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/kubescape/go-logger"
	"github.com/mikefarah/yq/v4/pkg/yqlib"
)

// NodeRelation is retained for source compatibility with earlier releases.
// Deprecated: the YAML editor no longer compares flattened node lists.
type NodeRelation int

func readDocuments(ctx context.Context, reader io.Reader, decoder yqlib.Decoder) (*list.List, error) {
	err := decoder.Init(reader)
	if err != nil {
		return nil, fmt.Errorf("error initializing the decoder, %w", err)
	}
	inputList := list.New()

	var currentIndex uint

	for {
		candidateNode, errorReading := decoder.Decode()

		if errors.Is(errorReading, io.EOF) {
			switch reader := reader.(type) {
			case *os.File:
				safelyCloseFile(ctx, reader)
			}
			return inputList, nil
		} else if errorReading != nil {
			return nil, fmt.Errorf("error decoding yaml file, %w", errorReading)
		}

		candidateNode.Document = currentIndex
		candidateNode.EvaluateTogether = true

		inputList.PushBack(candidateNode)

		currentIndex = currentIndex + 1
	}
}

func safelyCloseFile(ctx context.Context, file *os.File) {
	err := file.Close()
	if err != nil {
		logger.L().Ctx(ctx).Warning("Error Closing File")
	}
}
