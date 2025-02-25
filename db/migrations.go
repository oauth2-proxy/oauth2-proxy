package main

import (
	"embed"
	"fmt"
	"log"
	"net/url"
	"os"

	"github.com/amacneil/dbmate/v2/pkg/dbmate"
	_ "github.com/amacneil/dbmate/v2/pkg/driver/postgres"
)

//go:embed migrations/*.sql
var Migrations embed.FS

func Migrate(dbURL string) error {
	u, err := url.Parse(dbURL)
	if err != nil {
		return fmt.Errorf("failed to parse DATABASE_URL: %w", err)
	}

	db := dbmate.New(u)
	db.AutoDumpSchema = false
	db.Verbose = true
	db.FS = Migrations
	db.MigrationsDir = []string{"./migrations/"}

	if err := db.CreateAndMigrate(); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	return nil
}

func main() {
	if err := Migrate(os.Getenv("DATABASE_URL")); err != nil {
		log.Fatalf("failed to run migrations: %v", err)
	}
}
