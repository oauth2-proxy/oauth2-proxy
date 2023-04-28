package options

type ProviderLoader struct {

	// Type defines the type of ProviderLoader which can be single, config and postgres.
	// "single" referes to the single tenant providers.
	// "config" refers to multi-tenancy.
	// "postgres" refers to storing provider configuration in a podtgres store and load/delete multi-tenancy
	// providers while the service is alive.
	Type string // possible values are "single" and "config" and "postgres" for now

	// PostgresLoader contains configuration settings for PostgesLoader Type.
	PostgresLoader *PostgresLoader
}
