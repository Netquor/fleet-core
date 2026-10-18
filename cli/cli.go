// Package cli contains shared command-line helpers and utilities.
package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/micromdm/nanomdm/storage"
	"github.com/micromdm/nanomdm/storage/allmulti"
	"github.com/micromdm/nanomdm/storage/diskv"
	"github.com/micromdm/nanomdm/storage/file"
	"github.com/micromdm/nanomdm/storage/inmem"
	"github.com/micromdm/nanomdm/storage/mongodb"
	"github.com/micromdm/nanomdm/storage/mysql"
	"github.com/micromdm/nanomdm/storage/pgsql"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	"github.com/micromdm/nanolib/log"
)

var (
	ErrNoStorageOptions = errors.New("storage backend does not support options, please specify no (or empty) options")
	ErrMissingDSN       = errors.New("missing required DSN")
)

type StringAccumulator []string

func (s *StringAccumulator) String() string {
	return strings.Join(*s, ",")
}

func (s *StringAccumulator) Set(value string) error {
	*s = append(*s, value)
	return nil
}

type Storage struct {
	Storage StringAccumulator
	DSN     StringAccumulator
	Options StringAccumulator
}

func NewStorage() *Storage {
	return &Storage{}
}

func (s *Storage) Parse(logger log.Logger) (storage.AllStorage, error) {
	if len(s.Storage) != len(s.DSN) {
		return nil, errors.New("must have same number of storage and DSN flags")
	}
	if len(s.Options) > 0 && len(s.Storage) != len(s.Options) {
		return nil, errors.New("must have same number of storage and storage options flags")
	}
	// default storage and DSN pair
	if len(s.Storage) < 1 {
		s.Storage = append(s.Storage, "filekv")
		s.DSN = append(s.DSN, "dbkv")
	}
	var mdmStorage []storage.AllStorage
	for idx, storage := range s.Storage {
		dsn := s.DSN[idx]
		options := ""
		if len(s.Options) > 0 {
			options = s.Options[idx]
		}
		logger.Info(
			"msg", "storage setup",
			"storage", storage,
		)
		switch storage {
		case "file":
			if options != "enable_deprecated=1" {
				return nil, errors.New("file backend is deprecated; specify storage options to force enable")
			}
			if dsn == "" {
				return nil, ErrMissingDSN
			}
			fileStorage, err := file.New(dsn)
			if err != nil {
				return nil, err
			}
			mdmStorage = append(mdmStorage, fileStorage)
		case "mysql":
			mysqlStorage, err := mysqlStorageConfig(dsn, options, logger)
			if err != nil {
				return nil, err
			}
			mdmStorage = append(mdmStorage, mysqlStorage)
		case "pgsql":
			pgsqlStorage, err := pgsqlStorageConfig(dsn, options, logger)
			if err != nil {
				return nil, err
			}
			mdmStorage = append(mdmStorage, pgsqlStorage)
		case "mongodb":
			mongoStorage, err := mongodbStorageConfig(dsn, options, logger)
			if err != nil {
				return nil, err
			}
			mdmStorage = append(mdmStorage, mongoStorage)
		case "inmem":
			if options != "" {
				return nil, ErrNoStorageOptions
			}
			mdmStorage = append(mdmStorage, inmem.New())
		case "filekv":
			if dsn == "" {
				return nil, ErrMissingDSN
			}
			if options != "" {
				return nil, ErrNoStorageOptions
			}
			mdmStorage = append(mdmStorage, diskv.New(dsn))
		default:
			return nil, fmt.Errorf("unknown storage: %s", storage)
		}
	}
	if len(mdmStorage) < 1 {
		return nil, errors.New("no storage setup")
	}
	if len(mdmStorage) == 1 {
		return mdmStorage[0], nil
	}
	logger.Info("msg", "storage setup", "storage", "multi-storage", "count", len(mdmStorage))
	return allmulti.New(
		logger.With("component", "multi-storage"),
		mdmStorage...,
	), nil
}

func mysqlStorageConfig(dsn, options string, logger log.Logger) (*mysql.MySQLStorage, error) {
	logger = logger.With("storage", "mysql")
	opts := []mysql.Option{
		mysql.WithDSN(dsn),
		mysql.WithLogger(logger),
	}
	if options != "" {
		for k, v := range splitOptions(options) {
			switch k {
			case "delete":
				if v == "1" {
					opts = append(opts, mysql.WithDeleteCommands())
					logger.Debug("msg", "deleting commands")
				} else if v != "0" {
					return nil, fmt.Errorf("invalid value for delete option: %q", v)
				}
			case "conn_max_lifetime":
				d, err := time.ParseDuration(v)
				if err != nil {
					return nil, fmt.Errorf("invalid value for conn_max_lifetime option: %w", err)
				}
				opts = append(opts, mysql.WithConnMaxLifetime(d))
				logger.Debug("msg", "connection max lifetime", "duration", d.String())
			case "conn_max_idle_time":
				d, err := time.ParseDuration(v)
				if err != nil {
					return nil, fmt.Errorf("invalid value for conn_max_idle_time option: %w", err)
				}
				opts = append(opts, mysql.WithConnMaxIdleTime(d))
				logger.Debug("msg", "connection max idle time", "duration", d.String())
			default:
				return nil, fmt.Errorf("invalid option: %q", k)
			}
		}
	}
	return mysql.New(opts...)
}

func splitOptions(s string) map[string]string {
	out := make(map[string]string)
	opts := strings.Split(s, ",")
	for _, opt := range opts {
		optKAndV := strings.SplitN(opt, "=", 2)
		if len(optKAndV) < 2 {
			optKAndV = append(optKAndV, "")
		}
		out[optKAndV[0]] = optKAndV[1]
	}
	return out
}

func pgsqlStorageConfig(dsn, options string, logger log.Logger) (*pgsql.PgSQLStorage, error) {
	logger = logger.With("storage", "pgsql")
	opts := []pgsql.Option{
		pgsql.WithDSN(dsn),
		pgsql.WithLogger(logger),
	}
	if options != "" {
		for k, v := range splitOptions(options) {
			switch k {
			case "delete":
				if v == "1" {
					opts = append(opts, pgsql.WithDeleteCommands())
					logger.Debug("msg", "deleting commands")
				} else if v != "0" {
					return nil, fmt.Errorf("invalid value for delete option: %q", v)
				}
			default:
				return nil, fmt.Errorf("invalid option: %q", k)
			}
		}
	}
	return pgsql.New(opts...)
}

// mongodbStorageConfig sets up the MongoDB backend. The DSN is a MongoDB connection string (mongodb:// or mongodb+srv://); it needs a replica set,
// because commands are queued in transactions. Options: delete=1 (delete a command once acknowledged), database=<name> (default: the one in the
// DSN's path, else "nanomdm"), noindex=1 (do not create indexes at startup).
func mongodbStorageConfig(dsn, options string, logger log.Logger) (*mongodb.MongoDBStorage, error) {
	if dsn == "" {
		return nil, ErrMissingDSN
	}
	logger = logger.With("storage", "mongodb")
	opts := []mongodb.Option{mongodb.WithURI(dsn), mongodb.WithLogger(logger)}
	if options != "" {
		for k, v := range splitOptions(options) {
			switch k {
			case "delete":
				if v == "1" {
					opts = append(opts, mongodb.WithDeleteCommands())
					logger.Debug("msg", "deleting commands")
				} else if v != "0" {
					return nil, fmt.Errorf("invalid value for delete option: %q", v)
				}
			case "database":
				if v == "" {
					return nil, errors.New("empty value for database option")
				}
				opts = append(opts, mongodb.WithDatabase(v))
			case "noindex":
				if v == "1" {
					opts = append(opts, mongodb.WithoutIndexes())
				} else if v != "0" {
					return nil, fmt.Errorf("invalid value for noindex option: %q", v)
				}
			default:
				return nil, fmt.Errorf("invalid option: %q", k)
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return mongodb.New(ctx, opts...)
}
