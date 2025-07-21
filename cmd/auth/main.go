package main

import (
	"github.com/bmstu-itstech/auth/internal/app"
	"github.com/bmstu-itstech/auth/internal/config"
	"github.com/bmstu-itstech/auth/internal/lib/logger"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	cfg := config.MustLoad()

	log := logger.SetupLogger(cfg.Env)

	log.Info("starting auth service")

	application := app.New(
		log,
		cfg.GRPC.Port,
		cfg.Secret,
		cfg.TokenTTL,
		cfg.Postgres.PostgresUser,
		cfg.Postgres.PostgresPasswd,
		cfg.Postgres.PostgresEndpoint,
		cfg.Postgres.PostgresPort,
		cfg.Postgres.PostgresDBName,
		cfg.Postgres.PostgresDisable,
		cfg.Postgres.PostgresPublic,
		cfg.Postgres.PostgresDriverName,
		cfg.Postgres.PostgresMaxOpenConn,
		cfg.Postgres.PostgresConnIdleTime,
	)

	go application.GRPCSrv.MustStart()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	<-stop

	application.GRPCSrv.Stop()

	log.Info("stopping auth service")
}
