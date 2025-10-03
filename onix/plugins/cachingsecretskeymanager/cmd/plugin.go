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

	keymgr "github.com/google/dpi-accelerator/beckn-onix/plugins/cachingsecretskeymanager"

	plugin "github.com/beckn/beckn-onix/pkg/plugin/definition" // Plugin definitions will be imported from here.
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

	// Conditionally disable caching if the cache object is nil
	if cache == nil {
		cfg.SubscriberKeysCache = false
		cfg.NetworkKeysCache = false
	}
	return newKeyManager(ctx, cache, registry, cfg)
}

// parseConfig converts the map[string]string to the keyManager.Config struct.
func parseConfig(config map[string]string) (*keymgr.Config, error) {
	projectID, exists := config["projectID"]
	if !exists {
		return &keymgr.Config{}, errors.New("projectID not found in config")
	}

	// Initialize caching flags to false by default
	enableSubscriberKeysCache := false
	enableNetworkKeysCache := false

	// Check for SubscriberKeys caching config
	if subscriberKeysCache, exists := config["cachingSubscriberKeys"]; exists {
		caching, err := strconv.ParseBool(subscriberKeysCache)
		if err != nil {
			return &keymgr.Config{}, fmt.Errorf("invalid value for cachingSubscriberKeys: %s, must be true or false", subscriberKeysCache)
		}
		enableSubscriberKeysCache = caching
	}

	// Check for NetworkKeys caching config
	if networkKeysCache, exists := config["cachingNetworkKeys"]; exists {
		caching, err := strconv.ParseBool(networkKeysCache)
		if err != nil {
			return &keymgr.Config{}, fmt.Errorf("invalid value for cachingNetworkKeys: %s, must be true or false", networkKeysCache)
		}
		enableNetworkKeysCache = caching
	}

	return &keymgr.Config{
		ProjectID:           projectID,
		SubscriberKeysCache: enableSubscriberKeysCache,
		NetworkKeysCache:    enableNetworkKeysCache,
	}, nil
}

// Provider is the exported symbol that the plugin manager will look for.
var Provider = keyMgrProvider{}
