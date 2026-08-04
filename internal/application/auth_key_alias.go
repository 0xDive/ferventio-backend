package application

import configpkg "github.com/0xDive/ferventio-backend/internal/config"

func decodeAuthKey(value string) ([]byte, error) { return configpkg.DecodeAuthKey(value) }
func DecodeAuthKey(value string) ([]byte, error) { return configpkg.DecodeAuthKey(value) }
