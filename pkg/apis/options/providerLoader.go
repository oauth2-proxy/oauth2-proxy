package options

type ProviderLoader struct {
	Type           string // possible values are "single" and "config" and "postgres" for now
	PostgresLoader *PostgresLoader
}
