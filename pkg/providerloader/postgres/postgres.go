package postgres

import (
	"context"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"gorm.io/datatypes"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type PtgStore struct {
	configuration *options.Postgres
	db            *gorm.DB
}

type provider struct {
	ID           string `gorm:"embedded"`
	ProviderConf datatypes.JSON
}

func NewPostgresStore(c options.Postgres) (*PtgStore, error) {
	db, err := gorm.Open(postgres.Open(c.ConnectionString()), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(c.MaxConnections)

	res := db.Exec("create schema if not exists  " + c.Schema)
	if res.Error != nil {
		return nil, res.Error
	}

	err = db.AutoMigrate(&provider{})
	if err != nil {
		return nil, err
	}

	ps := &PtgStore{
		configuration: &c,
		db:            db,
	}

	return ps, nil
}

func (ps *PtgStore) Create(ctx context.Context, id string, providerconf []byte) error {

	provider := provider{ID: id, ProviderConf: providerconf}
	res := ps.db.WithContext(ctx).Create(&provider)
	if res.Error != nil {
		return newError(res.Error)
	}

	return nil
}

// if not found affected rows=0
func (ps *PtgStore) Update(ctx context.Context, id string, providerconf []byte) error {

	res := ps.db.WithContext(ctx).Model(&provider{}).Where("id = ?", id).Update("provider_conf", providerconf)
	if res.Error != nil {
		return newError(res.Error)
	}
	if res.RowsAffected == 0 {
		return NewNotFoundError("provider conf entry does not exist")
	}
	return nil
}

func (ps *PtgStore) Get(ctx context.Context, id string) (string, error) {

	var prov = &provider{}
	prov.ID = id
	res := ps.db.WithContext(ctx).First(prov)
	if res.Error != nil {
		return "", newError(res.Error)
	}
	return string(prov.ProviderConf), nil
}

func (ps *PtgStore) Delete(ctx context.Context, id string) error {

	res := ps.db.WithContext(ctx).Where("id = ?", id).Delete(&provider{})
	if res.Error != nil {
		return newError(res.Error)
	}
	if res.RowsAffected == 0 {
		return NewNotFoundError("config entry not found")
	}
	return nil
}
