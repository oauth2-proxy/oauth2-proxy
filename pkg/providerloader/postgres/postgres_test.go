package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"reflect"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func NewMock() (sqlmock.Sqlmock, *PtgStore) {
	var err error
	var mock sqlmock.Sqlmock
	var db *sql.DB

	var conf = options.Postgres{
		Host:           "localhost",
		Port:           5432,
		Database:       "postgres",
		Schema:         "oauth",
		User:           "",
		Password:       "",
		MaxConnections: 5,
	}

	db, mock, err = sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		log.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}

	dialector := postgres.New(postgres.Config{
		DSN:                  "sqlmock_db",
		DriverName:           "postgres",
		Conn:                 db,
		PreferSimpleProtocol: true,
	})

	gdb, err := gorm.Open(dialector, &gorm.Config{}) // open gorm db
	if err != nil {
		log.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}

	pts := PtgStore{
		configuration: &conf,
		db:            gdb,
	}

	return mock, &pts
}

func TestPostgresStore_Create(t *testing.T) {
	tests := []struct {
		name         string
		id           string
		providerConf string
		RowsAffected int64
		sqlError     error
		wantErr      bool
	}{
		{
			"provider config created successfully",
			"dummy",
			"clientid:xxx",
			1,
			nil,
			false,
		},
		{
			"provider config not created successfully",
			"",
			"clientid:xxx",
			0,
			fmt.Errorf("error"),
			true,
		},
		{
			"Network error in sql connection",
			"dummy",
			"clientid:xxx",
			0,
			fmt.Errorf("network timeout"),
			true,
		},
	}

	for i, test := range tests {
		mock, postgresStore := NewMock()

		mock.ExpectBegin()
		mock.ExpectExec("INSERT INTO \"providers\" (\"id\",\"provider_conf\") VALUES ($1,$2)").WithArgs(test.id, test.providerConf).WillReturnResult(sqlmock.NewResult(0, test.RowsAffected)).WillReturnError(test.sqlError)
		if test.sqlError != nil {
			mock.ExpectRollback()
		} else {
			mock.ExpectCommit()
		}

		err := postgresStore.Create(context.Background(), test.id, []byte(test.providerConf))
		gotErr := err != nil
		if test.wantErr != gotErr {
			t.Errorf("Create '%v': expectedError = %v, gotError = '%v'", i, test.wantErr, err)
		}

		err = mock.ExpectationsWereMet()
		if err != nil {
			t.Errorf("There were unfulfilled exceptions: %v", err)
		}
	}
}

func TestPostgresStore_Update(t *testing.T) {
	tests := []struct {
		name         string
		id           string
		providerConf []byte
		RowsAffected int64
		sqlError     error
		wantErr      bool
	}{
		{
			"provider config updated successfully",
			"tenant1",
			[]byte("clientid:xxx"),
			1,
			nil,
			false,
		},
		{
			"provider config not updated successfully",
			"tenant2",
			[]byte("clientid:xxx"),
			0,
			nil,
			true,
		},
		{
			"Network error in sql connection",
			"tenant3",
			[]byte("clientid:xxx"),
			0,
			fmt.Errorf("network timeout"),
			true,
		},
	}

	for i, test := range tests {
		mock, postgresStore := NewMock()

		mock.ExpectBegin()
		mock.ExpectExec("UPDATE \"providers\" SET \"provider_conf\"=$1 WHERE id = $2").WithArgs(test.providerConf, test.id).WillReturnResult(sqlmock.NewResult(0, test.RowsAffected)).WillReturnError(test.sqlError)

		if test.sqlError != nil {
			mock.ExpectRollback()
		} else {
			mock.ExpectCommit()
		}

		err := postgresStore.Update(context.Background(), test.id, test.providerConf)

		gotErr := err != nil
		if test.wantErr != gotErr {
			t.Errorf("Update '%v': expectedError = %v, gotError = '%v'", i, test.wantErr, err)
		}

		err = mock.ExpectationsWereMet()
		if err != nil {
			t.Errorf("There were unfulfilled exceptions: %v", err)
		}
	}
}

func TestPostgresStore_Get(t *testing.T) {

	tests := []struct {
		name         string
		id           string
		providerConf string
		sqlError     error
		wantErr      bool
	}{
		{
			"provider config returned successfully",
			"tenant1",
			"clientid:xxx",
			nil,
			false,
		},
		{
			"Network Error",
			"tenant2",
			"clientid:xxx",
			fmt.Errorf("network timeout"),
			true,
		},
	}
	for i, test := range tests {
		mock, postgresStore := NewMock()

		rows := sqlmock.NewRows([]string{"id", "provider_conf"}).AddRow(test.id, test.providerConf)

		mock.ExpectQuery("SELECT * FROM \"providers\" WHERE \"providers\".\"id\" = $1 ORDER BY \"providers\".\"id\" LIMIT 1").WithArgs(test.id).WillReturnRows(rows).WillReturnError(test.sqlError)
		providerConf, err := postgresStore.Get(context.Background(), test.id)

		if (providerConf != "") && (!reflect.DeepEqual(providerConf, test.providerConf)) {
			t.Errorf("Get '%v': expected provider config = %v, got = %v", i, test.providerConf, providerConf)
		}

		gotErr := err != nil
		if test.wantErr != gotErr {
			t.Errorf("Get '%v': expectedError = %v, gotError = '%v'", i, test.wantErr, err)
		}

		err = mock.ExpectationsWereMet()
		if err != nil {
			t.Errorf("There were unfulfilled exceptions: %v", err)
		}

	}
}

func TestPostgresStore_Delete(t *testing.T) {
	tests := []struct {
		name         string
		id           string
		RowsAffected int64
		sqlError     error
		wantErr      bool
	}{
		{
			"provider config deleted successfully",
			"tenant1",
			1,
			nil,
			false,
		},
		{
			"provider config not deleted successfully",
			"",
			0,
			fmt.Errorf("error"),
			true,
		},
		{
			"Network error in sql connection",
			"tenant3",
			0,
			fmt.Errorf("network timeout"),
			true,
		},
	}

	for i, test := range tests {
		mock, postgresStore := NewMock()

		mock.ExpectBegin()
		mock.ExpectExec("DELETE FROM \"providers\" WHERE id = $1").WithArgs(test.id).WillReturnResult(sqlmock.NewResult(0, test.RowsAffected)).WillReturnError(test.sqlError)

		if test.sqlError != nil {
			mock.ExpectRollback()
		} else {
			mock.ExpectCommit()
		}

		err := postgresStore.Delete(context.Background(), test.id)

		gotErr := err != nil
		if test.wantErr != gotErr {
			t.Errorf("delete  '%v': expectedError = %v, gotError = '%v'", i, test.wantErr, err)
		}

		err = mock.ExpectationsWereMet()
		if err != nil {
			t.Errorf("There were unfulfilled exceptions: %v", err)
		}
	}
}
