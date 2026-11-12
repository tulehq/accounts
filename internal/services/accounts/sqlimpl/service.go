// Package sqlimpl implements contracts.OrganizationProvider on a SQL
// database, SQLite in practice, reached through gas/database, with its schema
// applied by gas/migrate.
//
// There is at most one organization, so the organization table holds at most
// one row, and everything else in the database belongs to it. Each operation
// runs in one transaction.
package sqlimpl

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/gasmod/gas"

	"tule.dev/accounts/internal/contracts"
)

// Service stores the organization in the database db provides.
type Service struct {
	db         gas.DatabaseProvider
	migrations gas.MigrationManager
	settings   *OrganizationSettings
	now        func() time.Time
}

var (
	_ contracts.OrganizationProvider = (*Service)(nil)
	_ gas.Service                    = (*Service)(nil)
)

// NewService returns the constructor gas uses to build a Service whose
// management account is the one settings describes.
func NewService(settings *OrganizationSettings) func(
	db gas.DatabaseProvider,
	migrations gas.MigrationManager,
) *Service {
	return func(db gas.DatabaseProvider, migrations gas.MigrationManager) *Service {
		return &Service{
			db:         db,
			migrations: migrations,
			settings:   settings,
			now:        time.Now,
		}
	}
}

// Name identifies the service to gas.
func (s *Service) Name() string {
	return "tule/services/accounts/sql"
}

// Init registers the schema migrations, which gas applies once every service
// is initialized.
func (s *Service) Init(context.Context) error {
	s.migrations.RegisterSlice(s, migrations)
	return nil
}

// Close releases nothing; the database belongs to the database service.
func (s *Service) Close(context.Context) error {
	return nil
}

// inTx runs fn in one transaction, which commits only when fn returns nil.
func (s *Service) inTx(ctx context.Context, fn func(*sql.Tx) error) error {
	if err := s.db.WithTx(ctx, nil, fn); err != nil {
		return fmt.Errorf("%s: %w", s.Name(), err)
	}
	return nil
}

// stamp is how the store keeps a time: Unix milliseconds, the precision the
// wire carries.
func stamp(t time.Time) int64 {
	return t.UnixMilli()
}

func unstamp(ms int64) time.Time {
	return time.UnixMilli(ms).UTC()
}
