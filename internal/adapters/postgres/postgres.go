package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/jmoiron/sqlx"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type Adapter struct {
	db     *sqlx.DB
	logger *slog.Logger
}

func NewPostgresAdapter(
	PostgresUser,
	PostgresPasswd,
	PostgresEndpoint,
	PostgresPort,
	PostgresDBName,
	PostgresDisable,
	PostgresPublic,
	PostgresDriverName string,
	PostgresMaxOpenConn int,
	PostgresConnIdleTime time.Duration,
	logger *slog.Logger,
) (*Adapter, error) {
	psqlInfo := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=%s&search_path=%s",
		PostgresUser,
		PostgresPasswd,
		PostgresEndpoint,
		PostgresPort,
		PostgresDBName,
		PostgresDisable,
		PostgresPublic,
	)

	const op = "postgresql.Connect"

	log := logger.With(
		slog.String("op", op),
	)

	log.Info(psqlInfo)
	db, err := sqlx.Connect(PostgresDriverName, psqlInfo)

	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}

	db.SetMaxOpenConns(PostgresMaxOpenConn)
	db.SetConnMaxIdleTime(PostgresConnIdleTime)

	err = db.Ping()
	if err != nil {
		return nil, err
	}

	return &Adapter{
		db:     db,
		logger: log,
	}, nil
}

func (a *Adapter) Close() error {
	return a.db.Close()
}

func (a *Adapter) Exec(ctx context.Context, q string, args ...interface{}) (sql.Result, error) {
	const op = "postgresql.Exec"

	log := a.logger.With(
		slog.String("op", op),
	)

	start := time.Now()

	sqlRes, err := a.db.ExecContext(ctx, sqlx.Rebind(sqlx.DOLLAR, q), args...)

	log.Info(fmt.Sprintf("executed in %s", time.Since(start)))

	return sqlRes, err
}

func (a *Adapter) Select(ctx context.Context, dest interface{}, q string, args ...interface{}) error {
	const op = "postgresql.Select"

	log := a.logger.With(
		slog.String("op", op),
	)

	start := time.Now()

	err := a.db.SelectContext(ctx, dest, sqlx.Rebind(sqlx.DOLLAR, q), args...)

	log.Info(fmt.Sprintf("executed in %s", time.Since(start)))

	return err
}

func (a *Adapter) QueryRow(ctx context.Context, query string, args ...interface{}) *sql.Row {
	const op = "postgresql.QueryRow"

	log := a.logger.With(
		slog.String("op", op),
	)

	start := time.Now()

	row := a.db.QueryRowContext(ctx, query, args...)

	log.Info(fmt.Sprintf("executed in %s", time.Since(start)))

	return row
}
