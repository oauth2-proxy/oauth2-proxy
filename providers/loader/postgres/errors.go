package postgres

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
)

type errAlreadyExists string

func (er errAlreadyExists) Error() string {
	return string(er)
}

func NewAlreadyExistError(msg string) error {
	return errAlreadyExists(msg)
}

func (er errAlreadyExists) Is(err error) bool {
	_, ok := err.(errAlreadyExists)
	return ok
}

var ErrAlreadyExists = errAlreadyExists("")

type errNotFound string

func (er errNotFound) Error() string {
	return string(er)
}

func NewNotFoundError(msg string) error {
	return errNotFound(msg)
}

func (er errNotFound) Is(err error) bool {
	_, ok := err.(errNotFound)
	return ok
}

var ErrNotFound = errNotFound("")

func newError(err error) error {
	pgErr := &pgconn.PgError{}
	if errors.As(err, &pgErr) {
		if pgErr.Code == "23505" || pgErr.Code == "42P04" || pgErr.Code == "42710" {
			return NewAlreadyExistError(err.Error())
		}
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return NewNotFoundError(err.Error())
	}

	return err
}
