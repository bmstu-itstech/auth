package app

import (
	"github.com/bmstu-itstech/auth/internal/adapters/postgres"
	grpcapp "github.com/bmstu-itstech/auth/internal/app/grpc"
	repository "github.com/bmstu-itstech/auth/internal/repository/auth"
	service "github.com/bmstu-itstech/auth/internal/usecase/auth"
	"log/slog"
	"time"
)

type App struct {
	GRPCSrv *grpcapp.App
}

func New(
	log *slog.Logger,
	grpcPort int,
	secretKey string,
	tokenTTL time.Duration,
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
) *App {
	PostgresAdapter, err := postgres.NewPostgresAdapter(
		PostgresUser,
		PostgresPasswd,
		PostgresEndpoint,
		PostgresPort,
		PostgresDBName,
		PostgresDisable,
		PostgresPublic,
		PostgresDriverName,
		PostgresMaxOpenConn,
		PostgresConnIdleTime,
		log,
	)

	if err != nil {
		panic("unable to connect to postgres: " + err.Error())
	}

	repo := repository.NewRepository(log, PostgresAdapter)

	useCase := service.NewService(
		log,
		repo,
		repo,
		repo,
		tokenTTL,
		secretKey,
	)

	grpcApp := grpcapp.New(log, grpcPort, useCase)

	return &App{
		GRPCSrv: grpcApp,
	}
}
