package config

import (
	"flag"
	"github.com/ilyakaznacheev/cleanenv"
	"os"
	"time"
)

type Config struct {
	Env      string         `yaml:"env"`
	TokenTTL time.Duration  `yaml:"token_ttl" env-required:"true"`
	GRPC     GRPCConfig     `yaml:"grpc"`
	Secret   string         `yaml:"secret" env-required:"true"`
	Postgres PostgresConfig `yaml:"postgres"`
}

type GRPCConfig struct {
	Port    int           `yaml:"port"`
	Timeout time.Duration `yaml:"timeout"`
}

type PostgresConfig struct {
	PostgresDriverName   string        `yaml:"postgres_driver_name" env-required:"true"`
	PostgresPasswd       string        `yaml:"postgres_passwd" env-required:"true"`
	PostgresEndpoint     string        `yaml:"postgres_endpoint" env-required:"true"`
	PostgresUser         string        `yaml:"postgres_user" env-required:"true"`
	PostgresDBName       string        `yaml:"postgres_db_name" env-required:"true"`
	PostgresPort         string        `yaml:"postgres_port" env-required:"true"`
	PostgresDisable      string        `yaml:"postgres_disable" env-required:"true"`
	PostgresPublic       string        `yaml:"postgres_public" env-required:"true"`
	PostgresMaxOpenConn  int           `yaml:"postgres_max_open_conn" env-required:"true"`
	PostgresConnIdleTime time.Duration `yaml:"postgres_conn_idle_time" env-required:"true"`
}

func MustLoad() *Config {
	path := fetchConfigPath()
	if path == "" {
		panic("config file path is empty")
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		panic("config file does not exist " + path)
	}

	var cfg Config

	if err := cleanenv.ReadConfig(path, &cfg); err != nil {
		panic("failed to read config" + err.Error())
	}

	return &cfg
}

func fetchConfigPath() string {
	var res string

	flag.StringVar(&res, "config", "", "path to config file")
	flag.Parse()

	if res == "" {
		res = os.Getenv("CONFIG_PATH")
	}

	return res
}
