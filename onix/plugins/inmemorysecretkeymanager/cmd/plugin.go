// Copyright 2025 Google LLC
//
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

package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	// Import the new key manager package
	keymgr "github.com/google/dpi-accelerator/beckn-onix/plugins/inmemorysecretkeymanager"

	plugin "github.com/beckn/beckn-onix/pkg/plugin/definition" // Plugin definitions will be imported from here.
)

const (
	// Default TTLs if not provided in the config.
	defaultPrivateKeyTTLSeconds = 15   // Default to 15 seconds
	defaultPublicKeyTTLSeconds  = 3600 // Default to 1 hour
)

var newKeyManager = func(ctx context.Context, cache plugin.Cache, registryLookup plugin.RegistryLookup, cfg *keymgr.Config) (plugin.KeyManager, func() error, error) {
	return keymgr.New(ctx, cache, registryLookup, cfg)
}

// keyMgrProvider implements the KeyManagerProvider interface.
type keyMgrProvider struct{}

// New creates a new KeyManager instance.
func (kp keyMgrProvider) New(ctx context.Context, cache plugin.Cache, registry plugin.RegistryLookup, config map[string]string) (plugin.KeyManager, func() error, error) {
	cfg, err := parseConfig(config)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid config: %w", err)
	}

	// The main key manager constructor now handles the logic.
	// We pass the external cache (for network keys) directly to it.
	return newKeyManager(ctx, cache, registry, cfg)
}

// parseConfig converts the map[string]string to the keyManager.Config struct.
func parseConfig(config map[string]string) (*keymgr.Config, error) {
	projectID, exists := config["projectID"]
	if !exists || projectID == "" {
		return nil, errors.New("projectID not found or is empty in config")
	}

	// Default TTLs if not provided.
	privateKeyTTL := defaultPrivateKeyTTLSeconds 
	if ttlStr, exists := config["privateKeyCacheTTLSeconds"]; exists {
		ttl, err := strconv.Atoi(ttlStr)
		if err != nil || ttl <= 0 {
			return nil, fmt.Errorf("invalid value for privateKeyCacheTTLSeconds: %q, must be a positive integer", ttlStr)
		}
		privateKeyTTL = ttl
	}

	publicKeyTTL := defaultPublicKeyTTLSeconds 
	if ttlStr, exists := config["publicKeyCacheTTLSeconds"]; exists {
		ttl, err := strconv.Atoi(ttlStr)
		if err != nil || ttl <= 0 {
			return nil, fmt.Errorf("invalid value for publicKeyCacheTTLSeconds: %q, must be a positive integer", ttlStr)
		}
		publicKeyTTL = ttl
	}

	return &keymgr.Config{
		ProjectID: projectID,
		CacheTTL: keymgr.CacheTTL{
			PrivateKeysSeconds: privateKeyTTL,
			PublicKeysSeconds:  publicKeyTTL,
		},
	}, nil
}

// Provider is the exported symbol that the plugin manager will look for.
var Provider = keyMgrProvider{}
