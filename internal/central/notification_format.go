package central

import "webscan/internal/common"

// EventNotification exposes the existing, side-effect-free formatter for the
// v3 outbox dispatcher while the two storage implementations coexist.
func EventNotification(event common.Map) string { return eventNotice(event) }
