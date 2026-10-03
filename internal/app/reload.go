package app

import (
	"context"
	"sync/atomic"

	"github.com/perimeterd/perimeterd/internal/control"
)

type reloadRequest struct {
	ctx      context.Context
	expected string
	result   chan control.ReloadResult
	epoch    uint64
	digest   string
}
type reloadBridge struct {
	ready    atomic.Bool
	requests chan *reloadRequest
	done     <-chan struct{}
}

func newReloadBridge(done <-chan struct{}) *reloadBridge {
	return &reloadBridge{requests: make(chan *reloadRequest), done: done}
}

func (b *reloadBridge) handle(ctx context.Context, input control.ReloadRequest) control.ReloadResult {
	select {
	case <-b.done:
		return control.Failure("rejected", "shutting_down", "daemon is shutting down")
	default:
	}
	if !b.ready.Load() {
		return control.Failure("rejected", "not_ready", "daemon startup is not complete")
	}
	request := &reloadRequest{ctx: ctx, expected: input.ExpectConfigSHA256, result: make(chan control.ReloadResult, 1)}
	select {
	case b.requests <- request:
	case <-ctx.Done():
		return control.Failure("unknown", "timeout", "reload completion is unknown: request canceled")
	case <-b.done:
		return control.Failure("unknown", "shutting_down", "reload completion is unknown: daemon shutting down")
	}
	select {
	case result := <-request.result:
		return result
	case <-ctx.Done():
		return control.Failure("unknown", "timeout", "reload completion is unknown: request canceled")
	case <-b.done:
		select {
		case result := <-request.result:
			return result
		default:
		}
		return control.Failure("unknown", "shutting_down", "reload completion is unknown: daemon shutting down")
	}
}
