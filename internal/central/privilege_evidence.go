package central

import (
	"errors"

	"github.com/mkjang2000/Xe-AntiShell/protocol/model"
)

// New typed observations must retain their paired proof through central ingest.
// Existing event families keep their prior compatibility/validation behavior.
func validatePrivilegeObservation(event model.Event) error {
	if event.Type != "process.credential_change" {
		if event.Credential != nil {
			return errors.New("credential observation does not match event type")
		}
		return nil
	}
	c := event.Credential
	if c == nil || event.Source != "tetragon" || event.BootID == "" || event.Process.PID != c.TGID || event.Process.ExecID == "" || event.Process.StartTime.IsZero() || event.Execution != nil || event.File != nil || event.Network != nil {
		return errors.New("credential observation requires stable source identity and paired payload")
	}
	if err := c.Validate(); err != nil {
		return errors.New("invalid paired credential observation")
	}
	return nil
}
