// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may not use this file except in compliance with the License.
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
	"strings"
	"testing"
	"time"

	keymgr "github.com/google/dpi-accelerator/beckn-onix/plugins/secretskeymanager"

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
	t.Run("valid config", func(t *testing.T) {
		config := map[string]string{
			"projectID": "test-project",
		}
		want := keymgr.Config{
			ProjectID: "test-project",
		}
		got, err := parseConfig(config)
		if err != nil {
			t.Errorf("parseConfig() error = %v", err)
			return
		}
		if got.ProjectID != want.ProjectID {
			t.Errorf("parseConfig() = %v, want %v", got, want)
		}
	})
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
		config := map[string]string{
			"projectID": "test-project",
		}

		originalNewKeyManager := newKeyManager
		defer func() { newKeyManager = originalNewKeyManager }() // Restore it after the test

		newKeyManager = func(ctx context.Context, cache plugin.Cache, registry plugin.RegistryLookup, cfg *keymgr.Config) (plugin.KeyManager, func() error, error) {
			return &mockKeyManager{}, func() error { return nil }, nil
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
	var ErrNilCache = "nil cache provided"
	var ErrNilRegistryLookup = "nil registry lookup provided"

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
				return nil, nil, nil // This won't be called, as parsing fails first.
			},
			errContains: "projectID not found",
		},
		{
			name:   "nil cache",
			config: map[string]string{"projectID": "test"},
			cache:  nil,
			mockFunc: func(ctx context.Context, cache plugin.Cache, registry plugin.RegistryLookup, cfg *keymgr.Config) (plugin.KeyManager, func() error, error) {
				// This simulates the error that would be returned from the real `New` function.
				return nil, nil, &customError{s: ErrNilCache}
			},
			errContains: ErrNilCache,
		},
		{
			name:     "nil registry",
			config:   map[string]string{"projectID": "test"},
			cache:    &mockCache{},
			registry: nil,
			mockFunc: func(ctx context.Context, cache plugin.Cache, registry plugin.RegistryLookup, cfg *keymgr.Config) (plugin.KeyManager, func() error, error) {
				return nil, nil, &customError{s: ErrNilRegistryLookup}
			},
			errContains: ErrNilRegistryLookup,
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
	if m.get != nil {
		return m.get(ctx, key)
	}
	return "", nil
}

func (m *mockCache) Set(ctx context.Context, key string, value string, expiration time.Duration) error {
	if m.set != nil {
		return m.set(ctx, key, value, expiration)
	}
	return nil
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
	if m.lookup != nil {
		return m.lookup(ctx, req)
	}
	return nil, nil
}

// customError helps simulate unexported errors for testing purposes.
type customError struct {
	s string
}

func (e *customError) Error() string {
	return e.s
}