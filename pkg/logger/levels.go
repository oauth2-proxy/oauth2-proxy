package logger

// The following constants define the various levels available to the logging
const (
	// Info levels for informational logs that should be logged all the time.
	Info0 = 0
	Info1 = Info0 + 1
	Info2 = Info1 + 1

	// Debug levels for debug logs that should only be logged when trying to
	// diagnose some error
	Debug0 = 3
	Debug1 = Debug0 + 1
	Debug2 = Debug1 + 1

	// Trace levels for trace level logging that should only be logged in extreme
	// circumstances. These can be used to make the logs very chatty.
	Trace0 = 6
	Trace1 = Trace0 + 1
	Trace2 = Trace1 + 1
)

// The following constants should be used when logging in the various packages
// throughout the codebase. We control the levels here cerntrally and then alias
// them for use in the packages themselves.
const (
	// Core levels are used in the main package.
	CoreInfo  = Info0
	CoreDebug = Debug0
	CoreTrace = Trace0

	// Provider levels are used in the providers package.
	ProviderInfo  = Info1
	ProviderDebug = Debug1
	ProviderTrace = Trace1

	// Request levels are used in the requests package.
	RequestInfo  = Info2
	RequestDebug = Debug2
	RequestTrace = Trace2
)
