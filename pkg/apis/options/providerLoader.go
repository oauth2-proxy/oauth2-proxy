package options

type ProviderLoader struct {

	// Type defines the type of ProviderLoader which can be single, config and postgres.
	// "single" referes to the single provider.
	// "config" refers to multiple providers loaded from config file.
	// "postgres" refers to storing provider configuration in a podtgres store and load/delete
	// providers while the service is alive.
	Type string // possible values are "single" and "config" and "postgres" for now

	// PostgresLoader contains configuration settings for PostgesLoader Type.
	PostgresLoader *PostgresLoader
}
