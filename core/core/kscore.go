package core

import (
	"context"
)

type Kubescape struct {
	Ctx context.Context
}

func (ks *Kubescape) Context() context.Context {
	return ks.Ctx
}

func NewKubescape(ctx context.Context) *Kubescape {
	return &Kubescape{Ctx: ctx}
}
