package config

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const explicitEnvFileVariable = "FERVENTIO_ENV_FILE"

type configSource struct {
	envFilePath string
	fileValues  map[string]string
}

func loadConfigSource() (configSource, error) {
	path, explicit, err := resolveDotEnvPath()
	if err != nil {
		return configSource{}, err
	}

	source := configSource{fileValues: make(map[string]string)}
	if path == "" {
		return source, nil
	}

	file, err := os.Open(path)
	if err != nil {
		if !explicit && os.IsNotExist(err) {
			return source, nil
		}
		return configSource{}, fmt.Errorf("open dotenv file %q: %w", path, err)
	}
	defer file.Close()

	values, err := parseDotEnv(file)
	if err != nil {
		return configSource{}, fmt.Errorf("parse dotenv file %q: %w", path, err)
	}
	source.envFilePath = path
	source.fileValues = values
	return source, nil
}

func resolveDotEnvPath() (path string, explicit bool, err error) {
	if configured := strings.TrimSpace(os.Getenv(explicitEnvFileVariable)); configured != "" {
		absolute, err := filepath.Abs(configured)
		if err != nil {
			return "", true, fmt.Errorf("resolve %s: %w", explicitEnvFileVariable, err)
		}
		info, err := os.Stat(absolute)
		if err != nil {
			return "", true, fmt.Errorf("%s points to unavailable file %q: %w", explicitEnvFileVariable, absolute, err)
		}
		if !info.Mode().IsRegular() {
			return "", true, fmt.Errorf("%s must point to a regular file: %q", explicitEnvFileVariable, absolute)
		}
		return absolute, true, nil
	}

	workingDirectory, err := os.Getwd()
	if err != nil {
		return "", false, fmt.Errorf("resolve working directory: %w", err)
	}

	candidates := []string{
		filepath.Join(workingDirectory, ".env"),
		filepath.Join(workingDirectory, "server", ".env"),
		filepath.Join(workingDirectory, "..", ".env"),
		"/app/.env",
		"/run/secrets/ferventio.env",
	}
	if executable, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(executable), ".env"))
	}

	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		absolute, err := filepath.Abs(candidate)
		if err != nil {
			continue
		}
		if _, duplicate := seen[absolute]; duplicate {
			continue
		}
		seen[absolute] = struct{}{}

		info, err := os.Stat(absolute)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", false, fmt.Errorf("inspect dotenv candidate %q: %w", absolute, err)
		}
		if info.Mode().IsRegular() {
			return absolute, false, nil
		}
	}
	return "", false, nil
}

func parseDotEnv(reader io.Reader) (map[string]string, error) {
	values := make(map[string]string)
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := scanner.Text()
		if lineNumber == 1 {
			line = strings.TrimPrefix(line, "\ufeff")
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}

		separator := strings.IndexByte(line, '=')
		if separator <= 0 {
			return nil, fmt.Errorf("line %d: expected KEY=VALUE", lineNumber)
		}
		key := strings.TrimSpace(line[:separator])
		if !validDotEnvKey(key) {
			return nil, fmt.Errorf("line %d: invalid variable name %q", lineNumber, key)
		}
		value, err := parseDotEnvValue(strings.TrimSpace(line[separator+1:]))
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber, err)
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

func validDotEnvKey(key string) bool {
	if key == "" {
		return false
	}
	for index, char := range key {
		if index == 0 {
			if char != '_' && !unicode.IsLetter(char) {
				return false
			}
			continue
		}
		if char != '_' && !unicode.IsLetter(char) && !unicode.IsDigit(char) {
			return false
		}
	}
	return true
}

func parseDotEnvValue(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}

	switch raw[0] {
	case '\'':
		closing := strings.IndexByte(raw[1:], '\'')
		if closing < 0 {
			return "", fmt.Errorf("unterminated single-quoted value")
		}
		closing++
		if err := validateDotEnvTrailing(raw[closing+1:]); err != nil {
			return "", err
		}
		return raw[1:closing], nil
	case '"':
		closing := findClosingDoubleQuote(raw)
		if closing < 0 {
			return "", fmt.Errorf("unterminated double-quoted value")
		}
		if err := validateDotEnvTrailing(raw[closing+1:]); err != nil {
			return "", err
		}
		value, err := strconv.Unquote(raw[:closing+1])
		if err != nil {
			return "", fmt.Errorf("invalid double-quoted value: %w", err)
		}
		return value, nil
	default:
		return stripDotEnvInlineComment(raw), nil
	}
}

func findClosingDoubleQuote(raw string) int {
	escaped := false
	for index := 1; index < len(raw); index++ {
		switch {
		case escaped:
			escaped = false
		case raw[index] == '\\':
			escaped = true
		case raw[index] == '"':
			return index
		}
	}
	return -1
}

func validateDotEnvTrailing(raw string) error {
	trailing := strings.TrimSpace(raw)
	if trailing == "" || strings.HasPrefix(trailing, "#") {
		return nil
	}
	return fmt.Errorf("unexpected characters after quoted value")
}

func stripDotEnvInlineComment(raw string) string {
	for index, char := range raw {
		if char == '#' && index > 0 {
			previous := rune(raw[index-1])
			if unicode.IsSpace(previous) {
				return strings.TrimSpace(raw[:index])
			}
		}
	}
	return strings.TrimSpace(raw)
}

func (s configSource) value(name string) string {
	if value, exists := os.LookupEnv(name); exists && strings.TrimSpace(value) != "" {
		return value
	}
	return s.fileValues[name]
}

func (s configSource) valueOr(name, fallback string) string {
	if value := strings.TrimSpace(s.value(name)); value != "" {
		return value
	}
	return fallback
}

func (s configSource) duration(name string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(s.value(name))
	if value == "" {
		return fallback
	}
	if parsed, err := time.ParseDuration(value); err == nil && parsed > 0 {
		return parsed
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return fallback
}

func (s configSource) positiveInt(name string, fallback int) (int, error) {
	value := strings.TrimSpace(s.value(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return parsed, nil
}

func (s configSource) nonNegativeInt(name string, fallback int) (int, error) {
	value := strings.TrimSpace(s.value(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return 0, fmt.Errorf("%s must be a non-negative integer", name)
	}
	return parsed, nil
}

func (s configSource) boolean(name string, fallback bool) (bool, error) {
	value := strings.TrimSpace(s.value(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be true or false", name)
	}
	return parsed, nil
}

func (s configSource) positiveDuration(name string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(s.value(name))
	if value == "" {
		return fallback, nil
	}
	if parsed, err := time.ParseDuration(value); err == nil && parsed > 0 {
		return parsed, nil
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second, nil
	}
	return 0, fmt.Errorf("%s must be a positive duration", name)
}
