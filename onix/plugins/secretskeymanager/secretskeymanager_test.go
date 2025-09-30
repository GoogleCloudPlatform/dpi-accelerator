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

package secretskeymanager

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"

	"github.com/beckn/beckn-onix/pkg/model"
	plugin "github.com/beckn/beckn-onix/pkg/plugin/definition" // Plugin definitions will be imported from here.

	"github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mockSecretMgr implements the secretMgr interface for testing.
type mockSecretMgr struct {
	createSecret        func(context.Context, *secretmanagerpb.CreateSecretRequest, ...gax.CallOption) (*secretmanagerpb.Secret, error)
	addSecretVersion    func(context.Context, *secretmanagerpb.AddSecretVersionRequest, ...gax.CallOption) (*secretmanagerpb.SecretVersion, error)
	deleteSecret        func(context.Context, *secretmanagerpb.DeleteSecretRequest, ...gax.CallOption) error
	accessSecretVersion func(context.Context, *secretmanagerpb.AccessSecretVersionRequest, ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error)
	close               func() error
}

func (m *mockSecretMgr) CreateSecret(ctx context.Context, req *secretmanagerpb.CreateSecretRequest, opts ...gax.CallOption) (*secretmanagerpb.Secret, error) {
	return m.createSecret(ctx, req, opts...)
}

func (m *mockSecretMgr) AddSecretVersion(ctx context.Context, req *secretmanagerpb.AddSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.SecretVersion, error) {
	return m.addSecretVersion(ctx, req, opts...)
}

func (m *mockSecretMgr) DeleteSecret(ctx context.Context, req *secretmanagerpb.DeleteSecretRequest, opts ...gax.CallOption) error {
	return m.deleteSecret(ctx, req, opts...)
}

func (m *mockSecretMgr) AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	return m.accessSecretVersion(ctx, req, opts...)
}

func (m *mockSecretMgr) Close() error {
	return m.close()
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

func TestNew(t *testing.T) {
 t.Run("valid config", func(t *testing.T) {
		cfg := &Config{
			ProjectID: "test-project",
		}
		cache := &mockCache{}
		reg := &mockRegistry{}
		mockClient := &mockSecretMgr{} // Create a mock client

		// Test the internal constructor with the mock to bypass real authentication
		km, closer, err := newWithClient(cache, reg, cfg, mockClient)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if closer == nil || km == nil {
			t.Error("expected km and closer function, got nil")
		}
	})
}

func TestNewErrors(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		cache   plugin.Cache
		reg     plugin.RegistryLookup
		wantErr error
	}{
		{
			name:    "empty project ID",
			cfg:     &Config{},
			cache:   &mockCache{},
			reg:     &mockRegistry{},
			wantErr: ErrEmptyProjectID,
		},
		{
			name: "nil cache",
			cfg: &Config{
				ProjectID: "test-project",
			},
			cache:   nil,
			reg:     &mockRegistry{},
			wantErr: ErrNilCache,
		},
		{
			name: "nil registry lookup",
			cfg: &Config{
				ProjectID: "test-project",
			},
			cache:   &mockCache{},
			reg:     nil,
			wantErr: ErrNilRegistryLookup,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			_, _, err := New(ctx, tt.cache, tt.reg, tt.cfg)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("expected error %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestGenerateKeyset(t *testing.T) {
	km := &keyMgr{}
	keys, err := km.GenerateKeyset()
	if err != nil {
		t.Fatalf("GenerateKeyPairs() error = %v", err)
	}

	if len(keys.SigningPrivate) == 0 {
		t.Error("SigningPrivate key is empty")
	}
	if len(keys.SigningPublic) == 0 {
		t.Error("SigningPublic key is empty")
	}
	if len(keys.EncrPrivate) == 0 {
		t.Error("EncrPrivate key is empty")
	}
	if len(keys.EncrPublic) == 0 {
		t.Error("EncrPublic key is empty")
	}
	if len(keys.UniqueKeyID) == 0 {
		t.Error("UniqueKeyID is empty")
	}
}

func TestInsertKeyset(t *testing.T) {
	tests := []struct {
		name       string
		keyID      string
		keyset     *model.Keyset
		mockSecret *mockSecretMgr
	}{
		{
			name:  "valid store",
			keyID: "key1",
			keyset: &model.Keyset{
				UniqueKeyID:    "unique1",
				SigningPrivate: "test-signing-private",
				EncrPrivate:    "test-encr-private",
			},
			mockSecret: &mockSecretMgr{
				createSecret: func(ctx context.Context, req *secretmanagerpb.CreateSecretRequest, opts ...gax.CallOption) (*secretmanagerpb.Secret, error) {
					return &secretmanagerpb.Secret{}, nil
				},
				addSecretVersion: func(ctx context.Context, req *secretmanagerpb.AddSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.SecretVersion, error) {
					return &secretmanagerpb.SecretVersion{}, nil
				},
			},
		},
		{
			name:  "secret already exists - successful re-insert",
			keyID: "key1",
			keyset: &model.Keyset{
				UniqueKeyID:    "unique1",
				SigningPrivate: "test-signing-private",
				EncrPrivate:    "test-encr-private",
			},
			mockSecret: func() *mockSecretMgr {
				createCallCount := 0
				return &mockSecretMgr{
					createSecret: func(ctx context.Context, req *secretmanagerpb.CreateSecretRequest, opts ...gax.CallOption) (*secretmanagerpb.Secret, error) {
						createCallCount++
						if createCallCount == 1 {
							return nil, status.Error(codes.AlreadyExists, "secret already exists")
						}
						return &secretmanagerpb.Secret{}, nil
					},
					deleteSecret: func(ctx context.Context, req *secretmanagerpb.DeleteSecretRequest, opts ...gax.CallOption) error {
						return nil
					},
					addSecretVersion: func(ctx context.Context, req *secretmanagerpb.AddSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.SecretVersion, error) {
						return &secretmanagerpb.SecretVersion{}, nil
					},
				}
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			km := &keyMgr{
				projectID:    "test-project",
				secretClient: tt.mockSecret,
			}
			err := km.InsertKeyset(ctx, tt.keyID, tt.keyset)
			if err != nil {
				t.Errorf("InsertKeyset() error = %v", err)
			}
		})
	}
}

func TestInsertKeysetErrors(t *testing.T) {
	tests := []struct {
		name        string
		keyID       string
		keyset      *model.Keyset
		mockSecret  *mockSecretMgr
		errContains string
	}{
		{
			name:  "create secret fails",
			keyID: "key1",
			keyset: &model.Keyset{
				UniqueKeyID:    "unique1",
				SigningPrivate: "test-signing-private",
				EncrPrivate:    "test-encr-private",
			},
			mockSecret: &mockSecretMgr{
				createSecret: func(ctx context.Context, req *secretmanagerpb.CreateSecretRequest, opts ...gax.CallOption) (*secretmanagerpb.Secret, error) {
					return nil, fmt.Errorf("create secret API error")
				},
			},
			errContains: "failed to create secret",
		},
		{
			name:  "secret already exists, delete fails",
			keyID: "key1",
			keyset: &model.Keyset{
				UniqueKeyID:    "unique1",
				SigningPrivate: "test-signing-private",
				EncrPrivate:    "test-encr-private",
			},
			mockSecret: &mockSecretMgr{
				createSecret: func(ctx context.Context, req *secretmanagerpb.CreateSecretRequest, opts ...gax.CallOption) (*secretmanagerpb.Secret, error) {
					return nil, status.Error(codes.AlreadyExists, "secret already exists")
				},
				deleteSecret: func(ctx context.Context, req *secretmanagerpb.DeleteSecretRequest, opts ...gax.CallOption) error {
					return fmt.Errorf("delete failed") // Simulate delete failure.
				},
			},
			errContains: "failed to delete existing secret with same keyID",
		},
		{
			name:  "add secret version fails",
			keyID: "key1",
			keyset: &model.Keyset{
				UniqueKeyID:    "unique1",
				SigningPrivate: "test-signing-private",
				EncrPrivate:    "test-encr-private",
			},
			mockSecret: &mockSecretMgr{
				createSecret: func(ctx context.Context, req *secretmanagerpb.CreateSecretRequest, opts ...gax.CallOption) (*secretmanagerpb.Secret, error) {
					return &secretmanagerpb.Secret{}, nil
				},
				addSecretVersion: func(ctx context.Context, req *secretmanagerpb.AddSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.SecretVersion, error) {
					return nil, fmt.Errorf("add secret version failed")
				},
			},
			errContains: "failed to add secret version",
		},
		{
			name:        "empty key ID",
			keyID:       "",
			keyset:      &model.Keyset{},
			mockSecret:  &mockSecretMgr{},
			errContains: ErrEmptyKeyID.Error(),
		},
		{
			name:        "nil keyset",
			keyID:       "key1",
			keyset:      nil,
			mockSecret:  &mockSecretMgr{},
			errContains: ErrNilKeySet.Error(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			km := &keyMgr{
				projectID:    "test-project",
				secretClient: tt.mockSecret,
			}
			err := km.InsertKeyset(ctx, tt.keyID, tt.keyset)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("expected error containing %q, got %v", tt.errContains, err)
			}
		})
	}
}

func TestKeyset(t *testing.T) {
	ctx := context.Background()
	keyID := "key1"
	expectedKeyset := &model.Keyset{
		UniqueKeyID:    "unique1",
		SigningPrivate: "test-signing-private",
		EncrPrivate:    "test-encr-private",
		SigningPublic:  "test-signing-public",
		EncrPublic:     "test-encr-public",
	}

	mockSecret := &mockSecretMgr{
		accessSecretVersion: func(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			payload, _ := json.Marshal(expectedKeyset)
			return &secretmanagerpb.AccessSecretVersionResponse{
				Payload: &secretmanagerpb.SecretPayload{Data: payload},
			}, nil
		},
	}
	km := &keyMgr{
		projectID:    "test-project",
		secretClient: mockSecret,
	}

	retrievedKeyset, err := km.Keyset(ctx, keyID)
	if err != nil {
		t.Fatalf("Keyset() error = %v", err)
	}

	if retrievedKeyset.UniqueKeyID != expectedKeyset.UniqueKeyID {
		t.Errorf("Keyset UniqueKeyID = %v, want %v", retrievedKeyset.UniqueKeyID, expectedKeyset.UniqueKeyID)
	}
	if retrievedKeyset.SigningPrivate != expectedKeyset.SigningPrivate {
		t.Errorf("Keyset SigningPrivate = %v, want %v", retrievedKeyset.SigningPrivate, expectedKeyset.SigningPrivate)
	}
	if retrievedKeyset.EncrPrivate != expectedKeyset.EncrPrivate {
		t.Errorf("Keyset EncrPrivate = %v, want %v", retrievedKeyset.EncrPrivate, expectedKeyset.EncrPrivate)
	}
	if retrievedKeyset.SigningPublic != expectedKeyset.SigningPublic {
		t.Errorf("Keyset SigningPublic = %v, want %v", retrievedKeyset.SigningPublic, expectedKeyset.SigningPublic)
	}
	if retrievedKeyset.EncrPublic != expectedKeyset.EncrPublic {
		t.Errorf("Keyset EncrPublic = %v, want %v", retrievedKeyset.EncrPublic, expectedKeyset.EncrPublic)
	}
}

func TestKeysetErrors(t *testing.T) {
	tests := []struct {
		name        string
		keyID       string
		mockSecret  *mockSecretMgr
		errContains string
	}{
		{
			name:  "access secret fails",
			keyID: "key1",
			mockSecret: &mockSecretMgr{
				accessSecretVersion: func(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
					return nil, fmt.Errorf("access failed")
				},
			},
			errContains: "failed to access secret version",
		},
		{
			name:  "keys with keyID not found",
			keyID: "key1",
			mockSecret: &mockSecretMgr{
				accessSecretVersion: func(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
					return nil, status.Error(codes.NotFound, "not found")
				},
			},
			errContains: "keys for subscriberID: key1 not found",
		},
		{
			name:        "empty key ID",
			keyID:       "",
			mockSecret:  &mockSecretMgr{},
			errContains: ErrEmptyKeyID.Error(),
		},
		{
			name:  "unmarshal payload fails",
			keyID: "key1",
			mockSecret: &mockSecretMgr{
				accessSecretVersion: func(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
					return &secretmanagerpb.AccessSecretVersionResponse{
						Payload: &secretmanagerpb.SecretPayload{Data: []byte("{invalid json")},
					}, nil
				},
			},
			errContains: "failed to unmarshal payload",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			km := &keyMgr{
				projectID:    "test-project",
				secretClient: tt.mockSecret,
			}

			_, err := km.Keyset(ctx, tt.keyID)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("expected error containing %q, got %v", tt.errContains, err)
			}
		})
	}
}
func TestLookupNPKeys(t *testing.T) {
	subscriberID := "sub1"
	uniqueKeyID := "key1"
	signingPublic := "test-signing-public"
	encrPublic := "test-encr-public"

	tests := []struct {
		name            string
		subscriberID    string
		uniqueKeyID     string
		mockRegistry    *mockRegistry
		mockCache       *mockCache
		expectedSigning string
		expectedEncr    string
	}{
		{
			name:         "cache hit",
			subscriberID: subscriberID,
			uniqueKeyID:  uniqueKeyID,
			mockRegistry: &mockRegistry{}, // Not called in this scenario
			mockCache: &mockCache{
				get: func(ctx context.Context, key string) (string, error) {
					cachedKeyset := &model.Keyset{
						SigningPublic: signingPublic,
						EncrPublic:    encrPublic,
					}
					data, _ := json.Marshal(cachedKeyset)
					return string(data), nil
				},
				set: func(ctx context.Context, key string, value string, expiration time.Duration) error {
					t.Errorf("Set should not be called on cache hit")
					return nil
				},
			},
			expectedSigning: signingPublic,
			expectedEncr:    encrPublic,
		},
		{
			name:         "cache miss, registry success, cache set success",
			subscriberID: subscriberID,
			uniqueKeyID:  uniqueKeyID,
			mockRegistry: &mockRegistry{
				lookup: func(ctx context.Context, req *model.Subscription) ([]model.Subscription, error) {
					return []model.Subscription{
						{
							SigningPublicKey: signingPublic,
							EncrPublicKey:    encrPublic,
						},
					}, nil
				},
			},
			mockCache: &mockCache{
				get: func(ctx context.Context, key string) (string, error) {
					return "", errors.New("cache miss") // Simulate cache miss
				},
				set: func(ctx context.Context, key string, value string, expiration time.Duration) error {
					return nil // Simulate successful set
				},
			},
			expectedSigning: signingPublic,
			expectedEncr:    encrPublic,
		},
		{
			name:         "cache hit unmarshal error, then registry success",
			subscriberID: subscriberID,
			uniqueKeyID:  uniqueKeyID,
			mockRegistry: &mockRegistry{
				lookup: func(ctx context.Context, req *model.Subscription) ([]model.Subscription, error) {
					return []model.Subscription{
						{
							SigningPublicKey: signingPublic,
							EncrPublicKey:    encrPublic,
						},
					}, nil
				},
			},
			mockCache: &mockCache{
				get: func(ctx context.Context, key string) (string, error) {
					return "{invalid json", nil // Simulate unmarshal error from cache
				},
				set: func(ctx context.Context, key string, value string, expiration time.Duration) error {
					return nil
				},
			},
			expectedSigning: signingPublic,
			expectedEncr:    encrPublic,
		},
		{
			name:         "cache miss, registry success, cache set fails (should still return keys)",
			subscriberID: subscriberID,
			uniqueKeyID:  uniqueKeyID,
			mockRegistry: &mockRegistry{
				lookup: func(ctx context.Context, req *model.Subscription) ([]model.Subscription, error) {
					return []model.Subscription{
						{
							SigningPublicKey: signingPublic,
							EncrPublicKey:    encrPublic,
						},
					}, nil
				},
			},
			mockCache: &mockCache{
				get: func(ctx context.Context, key string) (string, error) {
					return "", errors.New("cache miss")
				},
				set: func(ctx context.Context, key string, value string, expiration time.Duration) error {
					return fmt.Errorf("cache set failed") // Simulate cache set failure
				},
			},
			expectedSigning: signingPublic,
			expectedEncr:    encrPublic,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			km := &keyMgr{
				registry: tt.mockRegistry,
				cache:    tt.mockCache,
			}

			signingPublic, encrPublic, err := km.LookupNPKeys(ctx, tt.subscriberID, tt.uniqueKeyID)
			if err != nil {
				t.Fatalf("LookupNPKeys() error = %v, wantErr %v", err, false)
			}
			if signingPublic != tt.expectedSigning {
				t.Errorf("LookupNPKeys() SigningPublic = %v, expected %v", signingPublic, tt.expectedSigning)
			}
			if encrPublic != tt.expectedEncr {
				t.Errorf("LookupNPKeys() EncrPublic = %v, expected %v", encrPublic, tt.expectedEncr)
			}
		})
	}
}

func TestLookupNPKeysErrors(t *testing.T) {
	ctx := context.Background()
	subscriberID := "sub1"
	uniqueKeyID := "key1"

	tests := []struct {
		name         string
		subscriberID string
		uniqueKeyID  string
		mockRegistry *mockRegistry
		mockCache    *mockCache
		errContains  string
	}{
		{
			name:         "empty subscriber ID",
			subscriberID: "",
			uniqueKeyID:  uniqueKeyID,
			mockRegistry: &mockRegistry{},
			mockCache:    &mockCache{},
			errContains:  ErrEmptySubscriberID.Error(),
		},
		{
			name:         "empty unique key ID",
			subscriberID: subscriberID,
			uniqueKeyID:  "",
			mockRegistry: &mockRegistry{},
			mockCache:    &mockCache{},
			errContains:  ErrEmptyUniqueKeyID.Error(),
		},
		{
			name:         "registry lookup fails",
			subscriberID: subscriberID,
			uniqueKeyID:  uniqueKeyID,
			mockRegistry: &mockRegistry{
				lookup: func(ctx context.Context, req *model.Subscription) ([]model.Subscription, error) {
					return nil, fmt.Errorf("registry lookup API error")
				},
			},
			mockCache: &mockCache{
				get: func(ctx context.Context, key string) (string, error) {
					return "", errors.New("cache miss")
				},
			},
			errContains: "failed to lookup registry: registry lookup API error",
		},
		{
			name:         "empty subscriber list from registry",
			subscriberID: subscriberID,
			uniqueKeyID:  uniqueKeyID,
			mockRegistry: &mockRegistry{
				lookup: func(ctx context.Context, req *model.Subscription) ([]model.Subscription, error) {
					return []model.Subscription{}, nil // Return empty list
				},
			},
			mockCache: &mockCache{
				get: func(ctx context.Context, key string) (string, error) {
					return "", errors.New("cache miss")
				},
			},
			errContains: ErrSubscriberNotFound.Error(),
		},
		{
			name:         "nil subscriber list from registry",
			subscriberID: subscriberID,
			uniqueKeyID:  uniqueKeyID,
			mockRegistry: &mockRegistry{
				lookup: func(ctx context.Context, req *model.Subscription) ([]model.Subscription, error) {
					return nil, nil // Return nil list
				},
			},
			mockCache: &mockCache{
				get: func(ctx context.Context, key string) (string, error) {
					return "", errors.New("cache miss")
				},
			},
			errContains: ErrSubscriberNotFound.Error(), // Should still be "not found"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			km := &keyMgr{
				registry: tt.mockRegistry,
				cache:    tt.mockCache,
			}

			_, _, err := km.LookupNPKeys(ctx, tt.subscriberID, tt.uniqueKeyID)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("LookupNPKeys() error = %v, want error containing %q", err, tt.errContains)
			}
		})
	}
}

func TestDeleteKeyset(t *testing.T) {
	t.Run("successful delete", func(t *testing.T) {
		ctx := context.Background()
		keyID := "key1"
		mockSecret := &mockSecretMgr{
			deleteSecret: func(ctx context.Context, req *secretmanagerpb.DeleteSecretRequest, opts ...gax.CallOption) error {
				return nil
			},
		}
		km := &keyMgr{
			projectID:    "test-project",
			secretClient: mockSecret,
		}
		err := km.DeleteKeyset(ctx, keyID)
		if err != nil {
			t.Errorf("DeletePrivateKeys() error = %v", err)
		}
	})
}

func TestDeleteKeysetErrors(t *testing.T) {
	tests := []struct {
		name       string
		keyID      string
		mockSecret *mockSecretMgr
	}{
		{
			name:  "delete fails",
			keyID: "key1",
			mockSecret: &mockSecretMgr{
				deleteSecret: func(ctx context.Context, req *secretmanagerpb.DeleteSecretRequest, opts ...gax.CallOption) error {
					return fmt.Errorf("")
				},
			},
		},
		{
			name:       "empty key ID",
			keyID:      "",
			mockSecret: &mockSecretMgr{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			km := &keyMgr{
				projectID:    "test-project",
				secretClient: tt.mockSecret,
			}
			err := km.DeleteKeyset(ctx, tt.keyID)
			if err == nil {
				t.Errorf("expected error, got nil")
			}
		})
	}
}

func TestClose(t *testing.T) {
	t.Run("successful close", func(t *testing.T) {
		mockSecret := &mockSecretMgr{
			close: func() error {
				return nil
			},
		}
		km := &keyMgr{
			secretClient: mockSecret,
		}
		err := km.close()
		if err != nil {
			t.Errorf("close() error = %v", err)
		}
	})
}

func TestCloseErrors(t *testing.T) {
	t.Run("close fails", func(t *testing.T) {
		expectedErr := fmt.Errorf("close failed")
		mockSecret := &mockSecretMgr{
			close: func() error {
				return expectedErr
			},
		}
		km := &keyMgr{
			secretClient: mockSecret,
		}
		err := km.close()
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		if !errors.Is(err, expectedErr) {
			t.Errorf("expected error %v, got %v", expectedErr, err)
		}
	})
}

func TestGenerateSecretID(t *testing.T) {
	tests := []struct {
		name    string
		keyID   string
		wantLen int // Expected length, considering truncation and hash.
	}{
		{
			name:    "valid keyID",
			keyID:   "test_subscriber-id",
			wantLen: len("test_subscriber-id") + 1 + hashSuffixLen,
		},
		{
			name:    "keyID with other special characters",
			keyID:   "my_sub!d@with#chars$",
			wantLen: len("my_sub-d-with-chars-") + 1 + hashSuffixLen,
		},
		{
			name:    "keyID with special characters",
			keyID:   "subid.char",
			wantLen: len("subid-char") + 1 + hashSuffixLen,
		},
		{
			name:    "keyID longer than maxPrefixLen",
			keyID:   strings.Repeat("a", maxPrefixLen+50), // Longer than maxPrefixLen
			wantLen: maxPrefixLen + 1 + hashSuffixLen,
		},
		{
			name:    "keyID exactly maxPrefixLen",
			keyID:   strings.Repeat("b", maxPrefixLen),
			wantLen: maxPrefixLen + 1 + hashSuffixLen,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateSecretID(tt.keyID)

			// Check length.
			if len(got) != tt.wantLen {
				t.Errorf("generateSecretID(%q) length = %v, want %v", tt.keyID, len(got), tt.wantLen)
			}

			// Check format: should end with base64url encoded SHA256 hash (43 chars).
			h := sha256.Sum256([]byte(tt.keyID))
			if !strings.HasSuffix(got, "_"+encodeBase64URL(h[:])) {
				t.Errorf("generateSecretID(%q) doesn't end with expected hash suffix. Got: %s", tt.keyID, got)
			}

			// Check if it contains invalid characters.
			if regexp.MustCompile(invalidCharsRegex).MatchString(got) {
				t.Errorf("generateSecretID(%q) contains invalid characters: %s", tt.keyID, got)
			}
		})
	}
}
