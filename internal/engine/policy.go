package engine

import (
	"context"
	"errors"
)

// ValidateActivePolicy checks the same historical protection/quality evidence
// required by a real active run, without connecting to mail or a scanner. This
// does not authorize mailbox work or establish model/archive continuity.
func (e *Engine) ValidateActivePolicy(ctx context.Context) error {
	if e.Store == nil || e.Config.Safety.Mode != "active" {
		return errors.New("active policy and its history are required")
	}
	e.setDefaults()
	return e.requireActivationQuality(ctx)
}
