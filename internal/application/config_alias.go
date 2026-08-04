package application

import configpkg "github.com/0xDive/ferventio-backend/internal/config"

// Config remains an alias during the application-layer migration. New process
// wiring should import internal/config directly.
type Config = configpkg.Config

var LoadConfig = configpkg.LoadConfig
