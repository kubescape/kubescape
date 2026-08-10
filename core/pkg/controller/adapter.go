package controller

import (
	"context"
	"fmt"

	kubescapev1 "github.com/kubescape/kubescape/v3/core/pkg/controller/apis/v1"
)

type ScanExecutor interface {
	Execute(ctx context.Context, req *kubescapev1.ScanRequest) error
}

type KubescapeAdapter struct {
}

func NewKubescapeAdapter() *KubescapeAdapter {
	return &KubescapeAdapter{}
}

func (a *KubescapeAdapter) Execute(ctx context.Context, req *kubescapev1.ScanRequest) error {
	fmt.Printf("[Adapter] Mocking execution for ScanRequest: %s (Type: %s)\n", req.Name, req.Spec.ScanType)
	return nil
}
