package core

import (
	"context"
)

type Kubescape struct {
	Ctx context.Context
}

func (ks *Kubescape) Context() context.Context {
	if ks == nil || ks.Ctx == nil {
		return context.Background()
	}
	return ks.Ctx
}

func (ks *Kubescape) SetContext(ctx context.Context) {
	if ks == nil {
		return
	}
	ks.Ctx = ctx
}

func NewKubescape(ctx context.Context) *Kubescape {
	return &Kubescape{Ctx: ctx}
}
