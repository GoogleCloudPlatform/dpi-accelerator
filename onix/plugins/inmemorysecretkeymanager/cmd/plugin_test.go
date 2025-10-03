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
	"strings"
	"testing"
	"time"

	keymgr "github.com/google/dpi-accelerator/beckn-onix/plugins/inmemorysecretkeymanager"
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
	testCases := []struct {
		name              string
		config            map[string]string
		wantProjectID     string
		wantPrivateKeyTTL int
		wantPublicKeyTTL  int
	}{
		{
			name: "valid full config",
			config: map[string]string{
				"projectID":                 "test-p",
				"privateKeyCacheTTLSeconds": "120",
				"publicKeyCacheTTLSeconds":  "240",
			},
			wantProjectID:     "test-p",
			wantPrivateKeyTTL: 120,
			wantPublicKeyTTL:  240,
		},
		{
			name:              "valid config with defaults",
			config:            map[string]string{"projectID": "test-p"},
			wantProjectID:     "test-p",
			wantPrivateKeyTTL: 15,   // Default
			wantPublicKeyTTL:  3600, // Default
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseConfig(tc.config)
			if err != nil {
				t.Fatalf("parseConfig() returned unexpected error: %v", err)
			}
			if got.ProjectID != tc.wantProjectID {
				t.Errorf("got ProjectID = %q, want %q", got.ProjectID, tc.wantProjectID)
			}
			if got.CacheTTL.PrivateKeysSeconds != tc.wantPrivateKeyTTL {
				t.Errorf("got PrivateKeysSeconds = %d, want %d", got.CacheTTL.PrivateKeysSeconds, tc.wantPrivateKeyTTL)
			}
			if got.CacheTTL.PublicKeysSeconds != tc.wantPublicKeyTTL {
				t.Errorf("got PublicKeysSeconds = %d, want %d", got.CacheTTL.PublicKeysSeconds, tc.wantPublicKeyTTL)
			}
		})
	}
}

func TestParseConfig_Errors(t *testing.T) {
	testCases := []struct {
		name    string
		config  map[string]string
		wantErr string
	}{
		{
			name:    "missing projectID",
			config:  map[string]string{"privateKeyCacheTTLSeconds": "120"},
			wantErr: "projectID not found or is empty in config",
		},
		{
			name:    "invalid private key TTL value",
			config:  map[string]string{"projectID": "test-p", "privateKeyCacheTTLSeconds": "abc"},
			wantErr: "invalid value for privateKeyCacheTTLSeconds: \"abc\", must be a positive integer",
		},
		{
			name:    "zero public key TTL value",
			config:  map[string]string{"projectID": "test-p", "publicKeyCacheTTLSeconds": "0"},
			wantErr: "must be a positive integer",
		},
		{
			name:    "negative private key TTL value",
			config:  map[string]string{"projectID": "test-p", "privateKeyCacheTTLSeconds": "-10"},
			wantErr: "must be a positive integer",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseConfig(tc.config)
			if err == nil {
				t.Fatal("parseConfig() expected an error, but got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("expected error message to contain %q, but got %q", tc.wantErr, err.Error())
			}
		})
	}
}

// --- Mocks for testing the provider's New method ---

type mockCache struct{}

func (m *mockCache) Get(ctx context.Context, key string) (string, error)                            { return "", nil }
func (m *mockCache) Set(ctx context.Context, key string, value string, expiration time.Duration) error { return nil }
func (m *mockCache) Delete(ctx context.Context, key string) error                                  { return nil }
func (m *mockCache) Clear(ctx context.Context) error                                               { return nil }
func (m *mockCache) Close() error                                                                  { return nil }

type mockRegistry struct{}

func (m *mockRegistry) Lookup(ctx context.Context, req *model.Subscription) ([]model.Subscription, error) {
	return nil, nil
}

// --- Tests for keyMgrProvider ---

func TestKeyMgrProviderNew(t *testing.T) {
	// THE FIX: Temporarily replace the real function with a mock one.
	originalNewKeyManager := newKeyManager
	defer func() { newKeyManager = originalNewKeyManager }()
	newKeyManager = func(ctx context.Context, cache plugin.Cache, registry plugin.RegistryLookup, cfg *keymgr.Config) (plugin.KeyManager, func() error, error) {
		return &mockKeyManager{}, func() error { return nil }, nil
	}

	config := map[string]string{
		"projectID": "test-project-from-provider",
	}
	kp := keyMgrProvider{}

	_, closer, err := kp.New(context.Background(), &mockCache{}, &mockRegistry{}, config)
	if err != nil {
		t.Fatalf("New() returned an unexpected error: %v", err)
	}
	if closer == nil {
		t.Error("expected a non-nil closer function")
	}
}

func TestKeyMgrProviderNew_Error(t *testing.T) {
	config := map[string]string{
		// Missing projectID
	}
	kp := keyMgrProvider{}
	_, _, err := kp.New(context.Background(), &mockCache{}, &mockRegistry{}, config)

	if err == nil {
		t.Fatal("expected error for invalid config, got nil")
	}
	if !strings.Contains(err.Error(), "projectID not found") {
		t.Errorf("expected error about missing projectID, got: %v", err)
	}
}