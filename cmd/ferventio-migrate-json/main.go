package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/0xDive/ferventio-backend/internal/config"
	"github.com/0xDive/ferventio-backend/internal/storage/postgres"
)

func main() {
	var directory string
	flag.StringVar(&directory, "directory", "./data", "directory containing legacy JSON state files")
	flag.Parse()

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		fmt.Fprintln(os.Stderr, "DATABASE_URL is required")
		os.Exit(2)
	}
	cfg := config.Config{
		DatabaseURL:             databaseURL,
		DatabaseMaxConns:        4,
		DatabaseMinConns:        1,
		DatabaseMaxConnLifetime: 30 * time.Minute,
		DatabaseMaxConnIdleTime: 5 * time.Minute,
		DatabaseConnectTimeout:  10 * time.Second,
		DatabaseMigrate:         true,
		AuthEncryptionKey:       os.Getenv("AUTH_ENCRYPTION_KEY"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	storage, err := postgres.OpenPostgresStorage(ctx, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer storage.Close()
	report, err := postgres.ImportLegacyState(ctx, storage, directory)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	encoded, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(encoded))
}
