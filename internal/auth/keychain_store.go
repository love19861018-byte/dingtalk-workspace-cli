// Copyright 2026 Alibaba Group
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	"github.com/DingTalk-Real-AI/dingtalk-workspace-cli/internal/keychain"
)

var (
	migrationOnce sync.Once
	migrationDone bool
)

// SaveTokenDataKeychain saves TokenData to the platform keychain.
// This is the new secure storage method using random master key.
func SaveTokenDataKeychain(data *TokenData) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal token data: %w", err)
	}
	// Zero sensitive data after use
	defer func() {
		for i := range jsonData {
			jsonData[i] = 0
		}
	}()

	if err := keychain.Set(keychain.Service, keychain.AccountToken, string(jsonData)); err != nil {
		return fmt.Errorf("save to keychain: %w", err)
	}
	return nil
}

// LoadTokenDataKeychain loads TokenData from the platform keychain.
func LoadTokenDataKeychain() (*TokenData, error) {
	jsonStr, err := keychain.Get(keychain.Service, keychain.AccountToken)
	if err != nil {
		return nil, fmt.Errorf("load from keychain: %w", err)
	}
	if jsonStr == "" {
		return nil, fmt.Errorf("no token data in keychain")
	}

	var data TokenData
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return nil, fmt.Errorf("parse token data: %w", err)
	}
	return &data, nil
}

// DeleteTokenDataKeychain removes TokenData from the platform keychain.
func DeleteTokenDataKeychain() error {
	return keychain.Remove(keychain.Service, keychain.AccountToken)
}

// TokenDataExistsKeychain checks if token data exists in keychain.
func TokenDataExistsKeychain() bool {
	return keychain.Exists(keychain.Service, keychain.AccountToken)
}

// EnsureMigration performs one-time migration from legacy .data to keychain.
// This should be called early in the auth flow (e.g., during GetAccessToken).
// The migration is idempotent and thread-safe.
func EnsureMigration(configDir string, logger *slog.Logger) {
	migrationOnce.Do(func() {
		result := keychain.MigrateFromLegacy(configDir)
		migrationDone = true

		if result.Migrated {
			if logger != nil {
				logger.Info("migrated token data to secure keychain storage",
					"from", result.FromPath,
					"backup", result.BackupPath)
			}
		} else if result.NeedRelogin {
			if logger != nil {
				logger.Warn("cannot migrate legacy token data, please re-login",
					"error", result.Error)
			}
		} else if result.Error != nil {
			if logger != nil {
				logger.Error("migration failed", "error", result.Error)
			}
		}
	})
}

// IsMigrationDone returns true if migration has been attempted.
func IsMigrationDone() bool {
	return migrationDone
}
