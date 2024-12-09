package audit

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var AuditErrorMetricCounter = promauto.NewCounter(prometheus.CounterOpts{
	Name: "oauth2_proxy_audit_errors_requests_total",
	Help: "Total number of failed audit requests.",
})
