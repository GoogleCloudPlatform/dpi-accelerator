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
	"net"
	"os" // Import the 'os' package
	"strings"
	"testing"
	"time"

	keymgr "github.com/google/dpi-accelerator/beckn-onix/plugins/secretskeymanager"
	"google.golang.org/grpc"

	"github.com/beckn/beckn-onix/pkg/model"
	plugin "github.com/beckn/beckn-onix/pkg/plugin/definition"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
)

// mockSecretServer provides a fake implementation of the Secret Manager gRPC service.
type mockSecretServer struct {
	secretmanagerpb.UnimplementedSecretManagerServiceServer
}

// setupTestServer starts a mock gRPC server and returns its address and a cleanup function.
func setupTestServer(t *testing.T) (string, func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	secretmanagerpb.RegisterSecretManagerServiceServer(s, &mockSecretServer{})

	go func() {
		_ = s.Serve(lis)
	}()

	cleanup := func() {
		s.Stop()
	}

	return lis.Addr().String(), cleanup
}

func TestParseConfig(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		config := map[string]string{
			"projectID": "test-project",
		}
		want := &keymgr.Config{
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
	// ... (This function is correct and needs no changes)
	tests := []struct {
		name        string
		config      map[string]string
		errContains string
	}{
		{
			name:        "missing projectID",
			config:      map[string]string{},
			errContains: "projectID not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseConfig(tt.config)
			if err == nil {
				t.Errorf("expected error, got nil")
			} else if !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("expected error containing '%s', got '%s'", tt.errContains, err.Error())
			}
		})
	}
}

func TestKeyMgrProviderNew(t *testing.T) {
	t.Run("valid configuration", func(t *testing.T) {
		addr, cleanup := setupTestServer(t)
		defer cleanup()

		// THE FIX: Use os.Setenv and defer to ensure cleanup
		originalAddr, isSet := os.LookupEnv("SECRET_MANAGER_EMULATOR_HOST")
		os.Setenv("SECRET_MANAGER_EMULATOR_HOST", addr)
		defer func() {
			if isSet {
				os.Setenv("SECRET_MANAGER_EMULATOR_HOST", originalAddr)
			} else {
				os.Unsetenv("SECRET_MANAGER_EMULATOR_HOST")
			}
		}()

		config := map[string]string{
			"projectID": "test-project",
		}
		cache := &mockCache{}
		registry := &mockRegistry{}
		kp := keyMgrProvider{}
		km, kmCleanup, err := kp.New(context.Background(), cache, registry, config)
		if err != nil {
			t.Errorf("New() error = %v", err)
			return
		}
		if km == nil {
			t.Error("New() returned nil KeyManager")
		}
		if kmCleanup == nil {
			t.Error("New() returned nil cleanup function")
		} else {
			if err := kmCleanup(); err != nil {
				t.Errorf("cleanup() error = %v", err)
			}
		}
	})
}

func TestKeyMgrProviderNewErrors(t *testing.T) {
	addr, cleanup := setupTestServer(t)
	defer cleanup()

	// THE FIX: Set the emulator host for the entire duration of this test function
	originalAddr, isSet := os.LookupEnv("SECRET_MANAGER_EMULATOR_HOST")
	os.Setenv("SECRET_MANAGER_EMULATOR_HOST", addr)
	defer func() {
		if isSet {
			os.Setenv("SECRET_MANAGER_EMULATOR_HOST", originalAddr)
		} else {
			os.Unsetenv("SECRET_MANAGER_EMULATOR_HOST")
		}
	}()

	tests := []struct {
		name     string
		config   map[string]string
		cache    plugin.Cache
		registry plugin.RegistryLookup
		wantErr  error
	}{
		{
			name: "invalid configuration",
			config: map[string]string{
				"invalid": "test-project",
			},
			cache:    &mockCache{},
			registry: &mockRegistry{},
			wantErr:  errors.New("projectID not found in config"),
		},
		{
			name: "nil cache",
			config: map[string]string{
				"projectID": "test-project",
			},
			cache:    nil,
			registry: &mockRegistry{},
			wantErr:  keymgr.ErrNilCache,
		},
		{
			name: "nil registry",
			config: map[string]string{
				"projectID": "test-project",
			},
			cache:    &mockCache{},
			registry: nil,
			wantErr:  keymgr.ErrNilRegistryLookup,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: We no longer need to set the env var inside the loop
			// because it's set for the parent test.

			kp := keyMgrProvider{}
			_, _, err := kp.New(context.Background(), tt.cache, tt.registry, tt.config)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr.Error()) {
				// This is line 199 from your error log
				t.Errorf("expected error containing '%v', got '%v'", tt.wantErr, err)
			}
		})
	}
}

// mockCache implements the Cache interface for testing.
type mockCache struct{}
func (m *mockCache) Get(ctx context.Context, key string) (string, error) { return "", nil }
func (m *mockCache) Set(ctx context.Context, key, value string, ttl time.Duration) error { return nil }
func (m *mockCache) Delete(ctx context.Context, key string) error { return nil }
func (m *mockCache) Clear(ctx context.Context) error { return nil }
func (m *mockCache) Close() error { return nil }

// mockRegistry implements the RegistryLookup interface for testing.
type mockRegistry struct{}
func (m *mockRegistry) Lookup(ctx context.Context, req *model.Subscription) ([]model.Subscription, error) {
	return nil, nil
}