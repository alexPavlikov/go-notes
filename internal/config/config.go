package config

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	LogLevel int      `mapstructure:"log_level"`
	Server   Server   `mapstructure:"server"`
	Redis    Redis    `mapstructure:"redis"`
	Postgres Postgres `mapstructure:"pg"`

	DBConnectTimeout time.Duration `mapstructure:"db_connect_timeout"`
	Secret           string        `mapstructure:"secret"`
}

type Server struct {
	Path string `mapstructure:"path"`
	Port int    `mapstructure:"port"`
}

type Redis struct {
	Server   `mapstructure:"server"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

type Postgres struct {
	Server   `mapstructure:"server"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	DBName   string `mapstructure:"db_name"`
}

func (s *Server) ToString() string {
	return fmt.Sprintf("%s:%d", s.Path, s.Port)
}

func Load() (*Config, error) {
	var cfg Config

	path, filename := fetchConfigPath()

	if path == "" || filename == "" {
		return nil, errors.New("path or filename to config empty")
	}

	cfg, err := initViper(filename, path, cfg)
	if err != nil {
		return nil, fmt.Errorf("init viper err: %w", err)
	}

	var level = slog.Level(cfg.LogLevel)

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})))

	return &cfg, nil
}

func fetchConfigPath() (path, filename string) {
	flag.StringVar(&path, "config_path", "", "config path")
	flag.StringVar(&filename, "config_filename", "", "config filename")

	flag.Parse()

	if path == "" {
		path = os.Getenv("CONFIG_PATH")
	}

	if filename == "" {
		filename = os.Getenv("CONFIG_FILENAME")
	}

	return path, filename
}

func initViper(filename string, path string, cfg Config) (Config, error) {
	viper.AddConfigPath(path)
	viper.SetConfigName(filename)
	viper.SetConfigType("yaml")

	if err := viper.ReadInConfig(); err != nil {
		return Config{}, fmt.Errorf("read in config err: %w", err)
	}

	if err := viper.Unmarshal(&cfg); err != nil {
		return Config{}, fmt.Errorf("config unmarshal err: %w", err)
	}

	return cfg, nil
}
