package audit

import "errors"

var (
	ErrPersitAuditEvent = errors.New("could not persist the audit event")
)
