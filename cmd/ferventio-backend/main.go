package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/0xDive/ferventio-backend/internal/application"
	"github.com/0xDive/ferventio-backend/internal/config"
	"github.com/0xDive/ferventio-backend/internal/push"
	"github.com/0xDive/ferventio-backend/internal/storage/postgres"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil {
		logger.Error("backend stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.LoadConfig()
	if err != nil {
		return err
	}
	if cfg.EnvFilePath != "" {
		logger.Info("dotenv configuration loaded", "path", cfg.EnvFilePath)
	}

	rootContext, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	storage, err := postgres.OpenPostgresStorage(rootContext, cfg)
	if err != nil {
		return err
	}
	defer storage.Close()
	logger.Info(
		"PostgreSQL storage ready",
		"max_connections", cfg.DatabaseMaxConns,
		"min_connections", cfg.DatabaseMinConns,
		"migrations", cfg.DatabaseMigrate,
	)

	var authRepository application.AuthRepository
	if cfg.AuthEnabled() {
		authRepository = storage
		logger.Info("Ferventio OAuth broker enabled", "redirect", cfg.TwitchRedirectURL)
	}

	sender, err := push.NewSender(rootContext, cfg)
	if err != nil {
		return err
	}
	if cfg.FirebaseMessagingEnabled() {
		logger.Info("Firebase Messaging enabled", "project_id", cfg.FirebaseProjectID)
	} else {
		logger.Info("Firebase Messaging disabled")
	}
	serverApplication := application.New(application.Dependencies{
		Config:        cfg,
		Registrations: storage,
		Auth:          authRepository,
		Sender:        sender,
		Deliveries:    storage,
		Audit:         storage,
		Settings:      storage,
		Readiness:     storage,
		Logger:        logger,
	})

	workerContext, cancelWorkers := context.WithCancel(rootContext)
	defer cancelWorkers()
	go serverApplication.RunBackgroundWorkers(workerContext)
	go serverApplication.RunUserChatEventSub(workerContext)

	httpServer := &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           serverApplication.Handler(),
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("Ferventio backend started", "address", cfg.ListenAddress)
		serverErrors <- httpServer.ListenAndServe()
	}()

	select {
	case <-rootContext.Done():
		logger.Info("shutdown signal received")
	case err := <-serverErrors:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}

	cancelWorkers()
	shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownContext); err != nil {
		return err
	}
	return nil
}
