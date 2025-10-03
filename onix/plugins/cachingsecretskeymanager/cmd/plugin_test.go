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
	"strings"
	"testing"
	"time"

	keymgr "github.com/google/dpi-accelerator/beckn-onix/plugins/cachingsecretskeymanager"
	"github.com/beckn/beckn-onix/pkg/model"
	plugin "github.com/beckn/beckn-onix/pkg/plugin/definition"
)

// mockKeyManager is a fake KeyManager that does nothing.
type mockKeyManager struct{}

func (m *mockKeyManager) GenerateKeyset() (*model.Keyset, error)       { return nil, nil }
func (m *mockKeyManager) InsertKeyset(context.Context, string, *model.Keyset) error { return nil }
func (m *mockKeyManager) Keyset(context.Context, string) (*model.Keyset, error) { return nil, nil }
func (m *mockKeyManager) DeleteKeyset(context.Context, string) error      { return nil }
func (m *mockKeyManager) LookupNPKeys(context.Context, string, string) (string, string, error) {
	return "", "", nil
}

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name                        string
		config                      map[string]string
		wantProjectID               string
		wantSubscriberKeysCache     bool
		wantNetworkKeysCache        bool
	}{
		{
			name:                    "default no caching flags",
			config:                  map[string]string{"projectID": "test-project"},
			wantProjectID:           "test-project",
			wantSubscriberKeysCache: false,
			wantNetworkKeysCache:    false,
		},
		{
			name:                    "subscriber keys caching true",
			config:                  map[string]string{"projectID": "test-project", "cachingSubscriberKeys": "true"},
			wantProjectID:           "test-project",
			wantSubscriberKeysCache: true,
			wantNetworkKeysCache:    false,
		},
		{
			name:                    "network keys caching true",
			config:                  map[string]string{"projectID": "test-project", "cachingNetworkKeys": "true"},
			wantProjectID:           "test-project",
			wantSubscriberKeysCache: false,
			wantNetworkKeysCache:    true,
		},
		{
			name:                    "both caching true",
			config:                  map[string]string{"projectID": "test-project", "cachingSubscriberKeys": "true", "cachingNetworkKeys": "true"},
			wantProjectID:           "test-project",
			wantSubscriberKeysCache: true,
			wantNetworkKeysCache:    true,
		},
		{
			name:                    "subscriber keys explicitly false, network true",
			config:                  map[string]string{"projectID": "test-project", "cachingSubscriberKeys": "false", "cachingNetworkKeys": "true"},
			wantProjectID:           "test-project",
			wantSubscriberKeysCache: false,
			wantNetworkKeysCache:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseConfig(tt.config)

			if err != nil {
				t.Errorf("parseConfig() for %s returned unexpected error = %v", tt.name, err)
				return
			}
			if got == nil {
				t.Errorf("parseConfig() for %s returned nil config, want non-nil", tt.name)
				return
			}

			if got.ProjectID != tt.wantProjectID {
				t.Errorf("parseConfig() for %s got ProjectID = %q, want %q", tt.name, got.ProjectID, tt.wantProjectID)
			}
			if got.SubscriberKeysCache != tt.wantSubscriberKeysCache {
				t.Errorf("parseConfig() for %s got SubscriberKeysCache = %t, want %t", tt.name, got.SubscriberKeysCache, tt.wantSubscriberKeysCache)
			}
			if got.NetworkKeysCache != tt.wantNetworkKeysCache {
				t.Errorf("parseConfig() for %s got NetworkKeysCache = %t, want %t", tt.name, got.NetworkKeysCache, tt.wantNetworkKeysCache)
			}
		})
	}
}

func TestParseConfigErrors(t *testing.T) {
	tests := []struct {
		name   string
		config map[string]string
	}{
		{
			name:   "missing projectID",
			config: map[string]string{},
		},
		{
			name:   "empty config",
			config: map[string]string{},
		},
		{
			name:   "invalid cachingSubscriberKeys value",
			config: map[string]string{"projectID": "test-project", "cachingSubscriberKeys": "invalid"},
		},
		{
			name:   "invalid cachingNetworkKeys value",
			config: map[string]string{"projectID": "test-project", "cachingNetworkKeys": "not_a_bool"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseConfig(tt.config)
			if err == nil {
				t.Errorf("expected error, got nil")
			}
		})
	}
}

func TestKeyMgrProviderNew(t *testing.T) {
	t.Run("valid configuration", func(t *testing.T) {
		originalNewKeyManager := newKeyManager
		defer func() { newKeyManager = originalNewKeyManager }()
		newKeyManager = func(ctx context.Context, cache plugin.Cache, registry plugin.RegistryLookup, cfg *keymgr.Config) (plugin.KeyManager, func() error, error) {
			return &mockKeyManager{}, func() error { return nil }, nil
		}
		config := map[string]string{
			"projectID": "test-project",
		}
		cache := &mockCache{}
		registry := &mockRegistry{}
		kp := keyMgrProvider{}
		km, cleanup, err := kp.New(context.Background(), cache, registry, config)
		if err != nil {
			t.Errorf("New() error = %v", err)
			return
		}
		if km == nil {
			t.Error("New() returned nil KeyManager")
		}
		if cleanup == nil {
			t.Error("New() returned nil cleanup function")
		} else {
			if err := cleanup(); err != nil {
				t.Errorf("cleanup() error = %v", err)
			}
		}
	})
}

func TestKeyMgrProviderNewErrors(t *testing.T) {
	tests := []struct {
		name        string
		config      map[string]string
		cache       plugin.Cache
		registry    plugin.RegistryLookup
		mockFunc    func(ctx context.Context, cache plugin.Cache, registry plugin.RegistryLookup, cfg *keymgr.Config) (plugin.KeyManager, func() error, error)
		errContains string
	}{
		{
			name:   "invalid configuration",
			config: map[string]string{"invalid": "test"},
			mockFunc: func(ctx context.Context, cache plugin.Cache, registry plugin.RegistryLookup, cfg *keymgr.Config) (plugin.KeyManager, func() error, error) {
				return nil, nil, nil
			},
			errContains: "projectID not found",
		},
		{
			name:     "nil registry",
			config:   map[string]string{"projectID": "test"},
			cache:    &mockCache{},
			registry: nil,
			mockFunc: func(ctx context.Context, cache plugin.Cache, registry plugin.RegistryLookup, cfg *keymgr.Config) (plugin.KeyManager, func() error, error) {
				return nil, nil, keymgr.ErrNilRegistryLookup
			},
			errContains: keymgr.ErrNilRegistryLookup.Error(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalNewKeyManager := newKeyManager
			defer func() { newKeyManager = originalNewKeyManager }()
			newKeyManager = tt.mockFunc

			kp := keyMgrProvider{}
			_, _, err := kp.New(context.Background(), tt.cache, tt.registry, tt.config)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("expected error containing '%s', got '%v'", tt.errContains, err)
			}
		})
	}
}

// mockCache implements the Cache interface for testing.
type mockCache struct {
	get    func(ctx context.Context, key string) (string, error)
	set    func(ctx context.Context, key string, value string, expiration time.Duration) error
	delete func(ctx context.Context, key string) error
	clear  func(ctx context.Context) error
	close  func() error
}

func (m *mockCache) Get(ctx context.Context, key string) (string, error) {
	return m.get(ctx, key)
}

func (m *mockCache) Set(ctx context.Context, key string, value string, expiration time.Duration) error {
	return m.set(ctx, key, value, expiration)
}

func (m *mockCache) Delete(ctx context.Context, key string) error {
	if m.delete != nil {
		return m.delete(ctx, key)
	}
	return nil
}

func (m *mockCache) Clear(ctx context.Context) error {
	if m.clear != nil {
		return m.clear(ctx)
	}
	return nil
}

func (m *mockCache) Close() error {
	if m.close != nil {
		return m.close()
	}
	return nil
}

// mockRegistry implements the RegistryLookup interface for testing.
type mockRegistry struct {
	lookup func(ctx context.Context, req *model.Subscription) ([]model.Subscription, error)
}

func (m *mockRegistry) Lookup(ctx context.Context, req *model.Subscription) ([]model.Subscription, error) {
	return m.lookup(ctx, req)
}
