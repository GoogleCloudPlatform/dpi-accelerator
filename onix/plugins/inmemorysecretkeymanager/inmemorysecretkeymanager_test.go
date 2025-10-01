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

package inmemorysecretkeymanager

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/beckn/beckn-onix/pkg/model"
	plugin "github.com/beckn/beckn-onix/pkg/plugin/definition"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// --- Mocks ---

// mockSecretMgr implements the secretMgr interface for testing.
type mockSecretMgr struct {
	mu                  sync.Mutex
	secrets             map[string][]byte
	accessCallCount     int32
	createCallCount     int32
	deleteCallCount     int32
	accessLatency       time.Duration
	createSecretErr     error
	addSecretVersionErr error
	deleteSecretErr     error
	accessSecretErr     error
	closeErr            error
}

func newMockSecretMgr(latency time.Duration) *mockSecretMgr {
	return &mockSecretMgr{
		secrets:       make(map[string][]byte),
		accessLatency: latency,
	}
}

func (m *mockSecretMgr) CreateSecret(ctx context.Context, req *secretmanagerpb.CreateSecretRequest, opts ...gax.CallOption) (*secretmanagerpb.Secret, error) {
	callNum := atomic.AddInt32(&m.createCallCount, 1)
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.createSecretErr != nil {
		if callNum == 1 && status.Code(m.createSecretErr) == codes.AlreadyExists {
			return nil, m.createSecretErr
		}
		if status.Code(m.createSecretErr) != codes.AlreadyExists {
			return nil, m.createSecretErr
		}
	}

	secretName := fmt.Sprintf("%s/secrets/%s", req.Parent, req.SecretId)
	return &secretmanagerpb.Secret{Name: secretName}, nil
}

func (m *mockSecretMgr) AddSecretVersion(ctx context.Context, req *secretmanagerpb.AddSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.SecretVersion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.addSecretVersionErr != nil {
		return nil, m.addSecretVersionErr
	}
	secretName := strings.TrimSuffix(req.Parent, "/versions/latest")
	if secretName == req.Parent {
		secretName = req.Parent
	}
	m.secrets[secretName+"/versions/latest"] = req.Payload.Data
	return &secretmanagerpb.SecretVersion{}, nil
}

func (m *mockSecretMgr) DeleteSecret(ctx context.Context, req *secretmanagerpb.DeleteSecretRequest, opts ...gax.CallOption) error {
	atomic.AddInt32(&m.deleteCallCount, 1)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deleteSecretErr != nil {
		return m.deleteSecretErr
	}
	delete(m.secrets, req.Name+"/versions/latest")
	return nil
}

func (m *mockSecretMgr) AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	atomic.AddInt32(&m.accessCallCount, 1)
	time.Sleep(m.accessLatency)

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.accessSecretErr != nil {
		return nil, m.accessSecretErr
	}
	payload, ok := m.secrets[req.Name]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "secret not found: %s", req.Name)
	}
	return &secretmanagerpb.AccessSecretVersionResponse{
		Payload: &secretmanagerpb.SecretPayload{Data: payload},
	}, nil
}

func (m *mockSecretMgr) Close() error { return m.closeErr }

// mockCache implements the plugin.Cache interface for testing.
type mockCache struct {
	mu     sync.Mutex
	store  map[string]string
	getErr error
	setErr error
}

func newMockCache() *mockCache {
	return &mockCache{store: make(map[string]string)}
}
func (m *mockCache) Get(ctx context.Context, key string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getErr != nil {
		return "", m.getErr
	}
	val, ok := m.store[key]
	if !ok {
		return "", errors.New("not found")
	}
	return val, nil
}
func (m *mockCache) Set(ctx context.Context, key string, value string, expiration time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.setErr != nil {
		return m.setErr
	}
	m.store[key] = value
	return nil
}
func (m *mockCache) Delete(ctx context.Context, key string) error { return nil }
func (m *mockCache) Clear(ctx context.Context) error              { return nil }
func (m *mockCache) Close() error                                 { return nil }

// mockRegistry implements the RegistryLookup interface for testing.
type mockRegistry struct {
	lookupFn func(ctx context.Context, req *model.Subscription) ([]model.Subscription, error)
}

func (m *mockRegistry) Lookup(ctx context.Context, req *model.Subscription) ([]model.Subscription, error) {
	if m.lookupFn != nil {
		return m.lookupFn(ctx, req)
	}
	return nil, errors.New("lookup function not implemented")
}

// --- Test Helper ---

func setupTestKeyManager(t *testing.T, sm secretMgr, rc plugin.Cache, rl plugin.RegistryLookup) *keyMgr {
	t.Helper()
	if sm == nil {
		sm = newMockSecretMgr(0)
	}
	if rc == nil {
		rc = newMockCache()
	}
	if rl == nil {
		rl = &mockRegistry{}
	}
	cfg := &Config{
		ProjectID: "test-project",
		CacheTTL:  CacheTTL{PrivateKeysSeconds: 3600, PublicKeysSeconds: 3600},
	}
	km := &keyMgr{
		projectID:         cfg.ProjectID,
		registry:          rl,
		redisCache:        rc,
		inMemoryCache:     &inMemoryCache{items: make(map[string]inMemoryCacheItem), ttl: time.Hour},
		publicKeyCacheTTL: time.Hour,
		requests:          make(map[string]*inFlightRequest),
		secretClient:      sm,
	}
	t.Cleanup(func() { _ = km.close() })
	return km
}

// --- Tests ---

func TestNew_Success(t *testing.T) {
	cfg := &Config{
        ProjectID: "test-project",
        CacheTTL:  CacheTTL{PrivateKeysSeconds: 60, PublicKeysSeconds: 120},
    }
    mockClient := newMockSecretMgr(0) // Create a mock client

    // Call the new testable function with the mock client
    _, closer, err := newWithClient(newMockCache(), &mockRegistry{}, cfg, mockClient)
    if err != nil {
        t.Fatalf("newWithClient() with valid config failed unexpectedly: %v", err)
    }
    if closer == nil {
        t.Fatal("newWithClient() returned a nil closer function")
    }
}

func TestNew_Errors(t *testing.T) {
	testCases := []struct {
		name    string
		cfg     *Config
		reg     plugin.RegistryLookup
		cache   plugin.Cache
		wantErr error
	}{
		{"nil registry", &Config{ProjectID: "p", CacheTTL: CacheTTL{1, 1}}, nil, newMockCache(), ErrNilRegistryLookup},
		{"empty project ID", &Config{CacheTTL: CacheTTL{1, 1}}, &mockRegistry{}, newMockCache(), ErrEmptyProjectID},
		{"invalid private key TTL", &Config{ProjectID: "p", CacheTTL: CacheTTL{0, 1}}, &mockRegistry{}, newMockCache(), ErrInvalidTTL},
		{"invalid public key TTL", &Config{ProjectID: "p", CacheTTL: CacheTTL{1, 0}}, &mockRegistry{}, newMockCache(), ErrInvalidTTL},
	}
	 for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            mockClient := newMockSecretMgr(0)
            _, _, err := newWithClient(tc.cache, tc.reg, tc.cfg, mockClient)
            if !errors.Is(err, tc.wantErr) {
                t.Errorf("expected error %v, got %v", tc.wantErr, err)
            }
        })
    }
}

func TestGenerateKeyset(t *testing.T) {
	km := &keyMgr{}
	keyset, err := km.GenerateKeyset()
	if err != nil {
		t.Fatalf("GenerateKeyset() error = %v", err)
	}
	if keyset.UniqueKeyID == "" || keyset.SigningPrivate == "" || keyset.SigningPublic == "" || keyset.EncrPrivate == "" || keyset.EncrPublic == "" {
		t.Error("GenerateKeyset() returned a keyset with one or more empty fields")
	}
}

func TestInsertKeyset(t *testing.T) {
	ctx := context.Background()
	keyID := "test-subscriber"
	keyset := &model.Keyset{UniqueKeyID: "test-key-123"}

	t.Run("happy path", func(t *testing.T) {
		mockSM := newMockSecretMgr(0)
		km := setupTestKeyManager(t, mockSM, nil, nil)
		err := km.InsertKeyset(ctx, keyID, keyset)
		if err != nil {
			t.Fatalf("InsertKeyset() failed: %v", err)
		}
		cached, found := km.inMemoryCache.Get(generateSecretID(keyID))
		if !found {
			t.Error("keyset was not found in in-memory cache after insert")
		}
		if cached.UniqueKeyID != keyset.UniqueKeyID {
			t.Error("cached keyset does not match inserted keyset")
		}
	})

t.Run("secret already exists - successfully replaces", func(t *testing.T) {
    mockSM := newMockSecretMgr(0)
    mockSM.createSecretErr = status.Error(codes.AlreadyExists, "secret exists")
    km := setupTestKeyManager(t, mockSM, nil, nil)
    
    keyID := "test-key-replace"
    newKeyset := &model.Keyset{UniqueKeyID: "new-key-789", SigningPublic: "new-public-key"}

    err := km.InsertKeyset(ctx, keyID, newKeyset)
    
    if err != nil {
        t.Fatalf("InsertKeyset() failed on replace: %v", err)
    }

    if atomic.LoadInt32(&mockSM.deleteCallCount) != 1 {
        t.Errorf("expected DeleteSecret to be called once, but was called %d times", mockSM.deleteCallCount)
    }
    if atomic.LoadInt32(&mockSM.createCallCount) != 2 {
        t.Errorf("expected CreateSecret to be called twice on replace, but was called %d times", mockSM.createCallCount)
    }

    secretID := generateSecretID(keyID)
    secretName := fmt.Sprintf("projects/test-project/secrets/%s/versions/latest", secretID)

    mockSM.mu.Lock()
    defer mockSM.mu.Unlock()
    
    storedPayload, ok := mockSM.secrets[secretName]
    if !ok {
        t.Fatalf("secret was not found in the mock store after replacement")
    }

    var storedKeyset model.Keyset
    if err := json.Unmarshal(storedPayload, &storedKeyset); err != nil {
        t.Fatalf("failed to unmarshal stored secret payload: %v", err)
    }

    if storedKeyset.UniqueKeyID != newKeyset.UniqueKeyID {
        t.Errorf("secret content was not updated correctly. got UniqueKeyID %q, want %q", storedKeyset.UniqueKeyID, newKeyset.UniqueKeyID)
    }
})
}

func TestInsertKeyset_Errors(t *testing.T) {
	ctx := context.Background()
	keyID := "test-subscriber"
	keyset := &model.Keyset{UniqueKeyID: "test-key-123"}

	testCases := []struct {
		name      string
		keyID     string
		keyset    *model.Keyset
		setupMock func(*mockSecretMgr)
		wantErr   string
	}{
		{"empty keyID", "", keyset, nil, ErrEmptyKeyID.Error()},
		{"nil keyset", keyID, nil, nil, ErrNilKeySet.Error()},
		{
			"create secret fails", keyID, keyset,
			func(m *mockSecretMgr) { m.createSecretErr = errors.New("creation failed") },
			"creation failed",
		},
		{
			"fails to delete on already-exists", keyID, keyset,
			func(m *mockSecretMgr) {
				m.createSecretErr = status.Error(codes.AlreadyExists, "secret exists")
				m.deleteSecretErr = errors.New("delete failed")
			},
			"delete failed",
		},
		{
			"add secret version fails", keyID, keyset,
			func(m *mockSecretMgr) { m.addSecretVersionErr = errors.New("add version failed") },
			"add version failed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockSM := newMockSecretMgr(0)
			if tc.setupMock != nil {
				tc.setupMock(mockSM)
			}
			km := setupTestKeyManager(t, mockSM, nil, nil)
			err := km.InsertKeyset(ctx, tc.keyID, tc.keyset)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestKeyset(t *testing.T) {
	ctx := context.Background()
	keyID := "test-subscriber"
	secretID := generateSecretID(keyID)
	keyset := &model.Keyset{UniqueKeyID: "test-key-456"}
	payload, _ := json.Marshal(keyset)

	t.Run("cache hit", func(t *testing.T) {
		mockSM := newMockSecretMgr(0)
		km := setupTestKeyManager(t, mockSM, nil, nil)
		km.inMemoryCache.Set(secretID, keyset)

		retrieved, err := km.Keyset(ctx, keyID)
		if err != nil {
			t.Fatalf("Keyset() failed on cache hit: %v", err)
		}
		if retrieved.UniqueKeyID != keyset.UniqueKeyID {
			t.Error("retrieved keyset from cache is incorrect")
		}
		if atomic.LoadInt32(&mockSM.accessCallCount) != 0 {
			t.Error("AccessSecretVersion was called on a cache hit")
		}
	})

	t.Run("cache miss - successful fetch", func(t *testing.T) {
		mockSM := newMockSecretMgr(0)
		secretName := fmt.Sprintf("projects/test-project/secrets/%s/versions/latest", secretID)
		mockSM.secrets[secretName] = payload
		km := setupTestKeyManager(t, mockSM, nil, nil)

		retrieved, err := km.Keyset(ctx, keyID)
		if err != nil {
			t.Fatalf("Keyset() failed on cache miss: %v", err)
		}
		if retrieved.UniqueKeyID != keyset.UniqueKeyID {
			t.Error("retrieved keyset from secret manager is incorrect")
		}
		if atomic.LoadInt32(&mockSM.accessCallCount) != 1 {
			t.Error("AccessSecretVersion was not called exactly once on a cache miss")
		}
		_, found := km.inMemoryCache.Get(secretID)
		if !found {
			t.Error("keyset was not cached after a successful fetch")
		}
	})
}

func TestKeyset_Errors(t *testing.T) {
	ctx := context.Background()

	testCases := []struct {
		name      string
		keyID     string
		setupMock func(*mockSecretMgr)
		wantErr   string
	}{
		{"empty keyID", "", nil, ErrEmptyKeyID.Error()},
		{
			"permission denied", "some-key",
			func(m *mockSecretMgr) { m.accessSecretErr = status.Error(codes.PermissionDenied, "denied") },
			"denied",
		},
		{
			"unmarshal fails", "good-key",
			func(m *mockSecretMgr) {
				secretID := generateSecretID("good-key")
				secretName := fmt.Sprintf("projects/test-project/secrets/%s/versions/latest", secretID)
				m.secrets[secretName] = []byte("this is not json")
			},
			"failed to unmarshal payload",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockSM := newMockSecretMgr(0)
			if tc.setupMock != nil {
				tc.setupMock(mockSM)
			}
			km := setupTestKeyManager(t, mockSM, nil, nil)
			_, err := km.Keyset(ctx, tc.keyID)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestKeyset_Concurrency(t *testing.T) {
	ctx := context.Background()
	keyID := "concurrent-key"
	keyset := &model.Keyset{UniqueKeyID: "concurrent-id"}
	payload, _ := json.Marshal(keyset)

	mockSM := newMockSecretMgr(20 * time.Millisecond) // Simulate latency
	secretID := generateSecretID(keyID)
	secretName := fmt.Sprintf("projects/test-project/secrets/%s/versions/latest", secretID)
	mockSM.secrets[secretName] = payload
	km := setupTestKeyManager(t, mockSM, nil, nil)

	var wg sync.WaitGroup
	numGoroutines := 20
	errs := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			k, err := km.Keyset(ctx, keyID)
			if err != nil {
				errs <- err
				return
			}
			if k.UniqueKeyID != keyset.UniqueKeyID {
				errs <- fmt.Errorf("got wrong key ID: %s", k.UniqueKeyID)
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("goroutine failed: %v", err)
	}

	finalCallCount := atomic.LoadInt32(&mockSM.accessCallCount)
	if finalCallCount != 1 {
		t.Errorf("expected AccessSecretVersion to be called once, but was called %d times", finalCallCount)
	}
}

func TestDeleteKeyset(t *testing.T) {
	ctx := context.Background()
	keyID := "key-to-delete"
	secretID := generateSecretID(keyID)
	mockSM := newMockSecretMgr(0)
	km := setupTestKeyManager(t, mockSM, nil, nil)
	km.inMemoryCache.Set(secretID, &model.Keyset{})

	err := km.DeleteKeyset(ctx, keyID)
	if err != nil {
		t.Fatalf("DeleteKeyset() failed: %v", err)
	}

	if _, found := km.inMemoryCache.Get(secretID); found {
		t.Error("keyset was not deleted from in-memory cache")
	}
	if atomic.LoadInt32(&mockSM.deleteCallCount) != 1 {
		t.Error("DeleteSecret was not called exactly once")
	}
}

func TestDeleteKeyset_Errors(t *testing.T) {
	ctx := context.Background()
	keyID := "key-to-delete"

	testCases := []struct {
		name      string
		keyID     string
		setupMock func(*mockSecretMgr)
		wantErr   string
	}{
		{"empty keyID", "", nil, ErrEmptyKeyID.Error()},
		{
			"delete fails in secret manager", keyID,
			func(m *mockSecretMgr) { m.deleteSecretErr = errors.New("delete failed") },
			"delete failed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockSM := newMockSecretMgr(0)
			if tc.setupMock != nil {
				tc.setupMock(mockSM)
			}
			km := setupTestKeyManager(t, mockSM, nil, nil)
			err := km.DeleteKeyset(ctx, tc.keyID)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestLookupNPKeys(t *testing.T) {
	ctx := context.Background()
	subID, keyID := "test-sub", "test-key"
	keys := model.Keyset{SigningPublic: "signing-key", EncrPublic: "encr-key"}
	keysPayload, _ := json.Marshal(&keys)

	t.Run("cache hit", func(t *testing.T) {
		mockRC := newMockCache()
		mockRC.store[fmt.Sprintf("%s_%s", subID, keyID)] = string(keysPayload)
		km := setupTestKeyManager(t, nil, mockRC, nil)

		signing, encr, err := km.LookupNPKeys(ctx, subID, keyID)
		if err != nil {
			t.Fatalf("LookupNPKeys() failed on cache hit: %v", err)
		}
		if signing != keys.SigningPublic || encr != keys.EncrPublic {
			t.Error("returned keys from cache are incorrect")
		}
	})

	t.Run("cache miss, registry success", func(t *testing.T) {
		mockRC := newMockCache()
		mockRL := &mockRegistry{
			lookupFn: func(ctx context.Context, req *model.Subscription) ([]model.Subscription, error) {
				if req.Subscriber.SubscriberID == subID && req.KeyID == keyID {
					return []model.Subscription{{SigningPublicKey: keys.SigningPublic, EncrPublicKey: keys.EncrPublic}}, nil
				}
				return nil, errors.New("not found")
			},
		}
		km := setupTestKeyManager(t, nil, mockRC, mockRL)

		signing, encr, err := km.LookupNPKeys(ctx, subID, keyID)
		if err != nil {
			t.Fatalf("LookupNPKeys() failed on registry lookup: %v", err)
		}
		if signing != keys.SigningPublic || encr != keys.EncrPublic {
			t.Error("returned keys from registry are incorrect")
		}
		if _, ok := mockRC.store[fmt.Sprintf("%s_%s", subID, keyID)]; !ok {
			t.Error("keys were not stored in redis cache after registry lookup")
		}
	})
}

func TestLookupNPKeys_Errors(t *testing.T) {
	ctx := context.Background()
	subID, keyID := "test-sub", "test-key"

	testCases := []struct {
		name      string
		subID     string
		keyID     string
		setupMock func() (plugin.Cache, plugin.RegistryLookup)
		wantErr   string
	}{
		{"empty subscriberID", "", keyID, nil, ErrEmptySubscriberID.Error()},
		{"empty uniqueKeyID", subID, "", nil, ErrEmptyUniqueKeyID.Error()},
		{
			"registry lookup fails", subID, keyID,
			func() (plugin.Cache, plugin.RegistryLookup) {
				rl := &mockRegistry{lookupFn: func(ctx context.Context, req *model.Subscription) ([]model.Subscription, error) {
					return nil, errors.New("lookup failed")
				}}
				return newMockCache(), rl
			},
			"lookup failed",
		},
		{
			"subscriber not found in registry", subID, keyID,
			func() (plugin.Cache, plugin.RegistryLookup) {
				rl := &mockRegistry{lookupFn: func(ctx context.Context, req *model.Subscription) ([]model.Subscription, error) {
					return []model.Subscription{}, nil // Empty slice
				}}
				return newMockCache(), rl
			},
			ErrSubscriberNotFound.Error(),
		},
		{
			"redis get fails but registry succeeds", subID, keyID,
			func() (plugin.Cache, plugin.RegistryLookup) {
				rc := newMockCache()
				rc.getErr = errors.New("redis dead") // Get will fail
				rl := &mockRegistry{lookupFn: func(ctx context.Context, req *model.Subscription) ([]model.Subscription, error) {
					// But registry will still work
					return []model.Subscription{{SigningPublicKey: "s", EncrPublicKey: "e"}}, nil
				}}
				return rc, rl
			},
			"", // No error expected, should recover from registry
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var mockRC plugin.Cache
			var mockRL plugin.RegistryLookup
			if tc.setupMock != nil {
				mockRC, mockRL = tc.setupMock()
			}
			km := setupTestKeyManager(t, nil, mockRC, mockRL)
			_, _, err := km.LookupNPKeys(ctx, tc.subID, tc.keyID)

			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("expected error containing %q, got %v", tc.wantErr, err)
				}
			} else if err != nil {
				t.Errorf("expected no error, but got %v", err)
			}
		})
	}
}

func TestClose_Success(t *testing.T) {
	mockSM := newMockSecretMgr(0)
	mockSM.closeErr = nil
	km := setupTestKeyManager(t, mockSM, nil, nil)
	km.inMemoryCache.Set("some-key", &model.Keyset{SigningPrivate: base64.StdEncoding.EncodeToString([]byte("secret"))})

	err := km.close()
	if err != nil {
		t.Fatalf("close() returned an unexpected error: %v", err)
	}
	if len(km.inMemoryCache.items) != 0 {
		t.Error("in-memory cache was not cleared on close")
	}
}

func TestClose_Error(t *testing.T) {
	mockSM := newMockSecretMgr(0)
	mockSM.closeErr = errors.New("close failed")
	km := setupTestKeyManager(t, mockSM, nil, nil)

	err := km.close()
	if err == nil || !strings.Contains(err.Error(), "close failed") {
		t.Errorf("expected close error, got %v", err)
	}
}

func TestInMemoryCache(t *testing.T) {
	t.Run("get and set", func(t *testing.T) {
		cache := &inMemoryCache{items: make(map[string]inMemoryCacheItem), ttl: time.Minute}
		keyset := &model.Keyset{UniqueKeyID: "1"}
		cache.Set("key1", keyset)
		retrieved, found := cache.Get("key1")
		if !found {
			t.Fatal("expected to find item in cache")
		}
		if retrieved.UniqueKeyID != "1" {
			t.Error("retrieved item is incorrect")
		}
	})

	t.Run("item expires", func(t *testing.T) {
		cache := &inMemoryCache{items: make(map[string]inMemoryCacheItem), ttl: 10 * time.Millisecond}
		cache.Set("key1", &model.Keyset{})
		time.Sleep(20 * time.Millisecond)
		_, found := cache.Get("key1")
		if found {
			t.Error("expected item to be expired and not found")
		}
	})

	t.Run("delete", func(t *testing.T) {
		cache := &inMemoryCache{items: make(map[string]inMemoryCacheItem), ttl: time.Minute}
		cache.Set("key1", &model.Keyset{})
		cache.Delete("key1")
		_, found := cache.Get("key1")
		if found {
			t.Error("found item in cache after it was deleted")
		}
	})
}

func TestSecurelyWipeKeyset(t *testing.T) {
	testCases := []struct {
		name   string
		keyset *model.Keyset
	}{
		{"nil keyset", nil},
		{
			"valid keyset",
			&model.Keyset{
				SigningPrivate: base64.StdEncoding.EncodeToString([]byte("secret1")),
				EncrPrivate:    base64.StdEncoding.EncodeToString([]byte("secret2")),
				SigningPublic:  "public1",
			},
		},
		{
			"invalid base64 strings",
			&model.Keyset{SigningPrivate: "not-base64"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.keyset == nil {
				securelyWipeKeyset(nil) // Should not panic
				return
			}

			originalPublic := tc.keyset.SigningPublic
			securelyWipeKeyset(tc.keyset)

			if tc.keyset.SigningPrivate != "" || tc.keyset.EncrPrivate != "" {
				t.Error("keyset private fields were not cleared after zeroize")
			}
			if tc.keyset.SigningPublic != originalPublic {
				t.Error("public key field was incorrectly modified")
			}
		})
	}
}

func TestGenerateSecretID(t *testing.T) {
	testCases := []struct {
		name       string
		input      string
		wantPrefix string
	}{
		{"simple ID", "subscriber-1", "subscriber-1"},
		{"with invalid chars", "subscriber@1/com", "subscriber-1-com"},
		{"long ID gets truncated", strings.Repeat("a", 300), strings.Repeat("a", maxPrefixLen)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := generateSecretID(tc.input)
			if len(got) > maxSecretIDLen {
				t.Errorf("generated secret ID is too long: got %d, max %d", len(got), maxSecretIDLen)
			}
			if !strings.HasPrefix(got, tc.wantPrefix+"_") {
				t.Errorf("generated secret ID prefix = %q, want %q", got, tc.wantPrefix)
			}
		})
	}
}



// --- Benchmarks ---

// mockBenchSecretMgr is a mock implementation of the secretMgr interface for benchmarking.
type mockBenchSecretMgr struct {
	mu            sync.Mutex
	secrets       map[string][]byte
	callCount     int32
	accessLatency time.Duration
}

// newMockBenchSecretMgr creates a new mock secret manager for benchmarking.
func newMockBenchSecretMgr(latency time.Duration) *mockBenchSecretMgr {
	return &mockBenchSecretMgr{
		secrets:       make(map[string][]byte),
		accessLatency: latency,
	}
}

// AccessSecretVersion simulates fetching a secret, adding a configurable delay.
func (m *mockBenchSecretMgr) AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	atomic.AddInt32(&m.callCount, 1)

	// Simulate network latency to the backend (e.g., Google Secret Manager).
	time.Sleep(m.accessLatency)

	m.mu.Lock()
	defer m.mu.Unlock()
	payload, ok := m.secrets[req.Name]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "secret not found: %s", req.Name)
	}
	return &secretmanagerpb.AccessSecretVersionResponse{
		Payload: &secretmanagerpb.SecretPayload{Data: payload},
	}, nil
}

func (m *mockBenchSecretMgr) CreateSecret(context.Context, *secretmanagerpb.CreateSecretRequest, ...gax.CallOption) (*secretmanagerpb.Secret, error) {
	return nil, nil 
}
func (m *mockBenchSecretMgr) AddSecretVersion(context.Context, *secretmanagerpb.AddSecretVersionRequest, ...gax.CallOption) (*secretmanagerpb.SecretVersion, error) {
	return nil, nil 
}
func (m *mockBenchSecretMgr) DeleteSecret(context.Context, *secretmanagerpb.DeleteSecretRequest, ...gax.CallOption) error {
	return nil 
}
func (m *mockBenchSecretMgr) Close() error {
	return nil 
}

// mockRegistryLookup is a minimal mock to satisfy the New() function's requirement.
type mockRegistryLookup struct{}

// Lookup now correctly returns []model.Subscription to match the interface.
func (m *mockRegistryLookup) Lookup(ctx context.Context, sub *model.Subscription) ([]model.Subscription, error) {
	// This method doesn't need to do anything for the Keyset benchmarks.
	return nil, nil
}

// setupBenchKeyManager is a helper function to correctly initialize the key manager for tests.
func setupBenchKeyManager(b *testing.B, mock secretMgr) *keyMgr {
	// Create a valid config for the key manager.
	 cfg := &Config{
        ProjectID: "bench-project",
        CacheTTL: CacheTTL{
            PrivateKeysSeconds: 3600,
            PublicKeysSeconds:  3600,
        },
    }

    // Call the testable constructor directly with the provided mock.
    km, closer, err := newWithClient(nil, &mockRegistryLookup{}, cfg, mock)
    if err != nil {
        b.Fatalf("Failed to create key manager for benchmark: %v", err)
    }

    // Use b.Cleanup to ensure the closer function is called when the benchmark finishes.
    b.Cleanup(func() {
        if err := closer(); err != nil {
            b.Errorf("Error during cleanup: %v", err)
        }
    })

    return km
}

// BenchmarkKeyset_CacheHit measures the performance of fetching a key that is already in the in-memory cache.
// This should be extremely fast as it avoids any network calls or complex logic.
func BenchmarkKeyset_CacheHit(b *testing.B) {
	mock := newMockBenchSecretMgr(0) // No latency needed as it should not be called.
	km := setupBenchKeyManager(b, mock)

	// Pre-populate the cache with a test key.
	testKeyID := "my-cached-key"
	secretID := generateSecretID(testKeyID)
	keyset := &model.Keyset{UniqueKeyID: "123"}
	km.inMemoryCache.Set(secretID, keyset)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := km.Keyset(context.Background(), testKeyID)
		if err != nil {
			b.Fatalf("Keyset failed unexpectedly on a cache hit: %v", err)
		}
	}
}

// BenchmarkKeyset_CacheMiss_Parallel measures performance under concurrent load for a key that is not in the cache.
func BenchmarkKeyset_CacheMiss_Parallel(b *testing.B) {
	// Simulate a 50ms network latency for fetching the secret.
	mock := newMockBenchSecretMgr(50 * time.Millisecond)
	km := setupBenchKeyManager(b, mock)

	testKeyID := "my-uncached-key"
	secretID := generateSecretID(testKeyID)
	secretName := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", km.projectID, secretID)

	// Prepare the secret payload that the mock will return.
	keyset := &model.Keyset{UniqueKeyID: "456", SigningPublic: "abc", EncrPublic: "xyz"}
	payload, err := json.Marshal(keyset)
	if err != nil {
		b.Fatalf("Failed to marshal keyset: %v", err)
	}
	mock.secrets[secretName] = payload

	b.ResetTimer()
	b.ReportAllocs()

	// Run the core logic in parallel to simulate many concurrent requests for the same key.
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := km.Keyset(context.Background(), testKeyID)
			if err != nil {
				// Use b.Errorf for non-fatal errors in parallel tests.
				b.Errorf("Keyset failed: %v", err)
			}
		}
	})

	b.StopTimer()

	// After all parallel executions are done, check the call count.
	finalCallCount := atomic.LoadInt32(&mock.callCount)
	b.Logf("Total calls to Secret Manager for %d requests: %d", b.N, finalCallCount)

	// The core assertion: The mock should have been called only ONCE.
	// All other b.N-1 requests should have waited for the result from the first "leader" request.
	if finalCallCount > 1 {
		b.Errorf("Thundering herd prevention failed! Expected 1 call to Secret Manager, but got %d", finalCallCount)
	}
}

// BenchmarkKeyset_Parallel_Scenarios tests different parallel access patterns.
func BenchmarkKeyset_Parallel_Scenarios(b *testing.B) {
	const numKeys = 200
	const projectID = "bench-project" 
	mock := newMockBenchSecretMgr(40 * time.Millisecond) 

	// --- Setup: Pre-generate 200 unique keys and populate the mock secret manager ---
	keyIDs := make([]string, numKeys)
	for i := 0; i < numKeys; i++ {
		keyID := fmt.Sprintf("parallel-key-%d", i)
		keyIDs[i] = keyID

		secretID := generateSecretID(keyID)
		secretName := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", projectID, secretID)
		keyset := &model.Keyset{UniqueKeyID: fmt.Sprintf("uid-%d", i)}
		payload, _ := json.Marshal(keyset)
		mock.secrets[secretName] = payload
	}

	// --- Sub-benchmark 1: Parallel Cache Miss (Cache Warmup) ---
	b.Run("ParallelMiss_Warmup", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			// A new key manager is created for each run to ensure the cache is empty.
			km := setupBenchKeyManager(b, mock)
			var wg sync.WaitGroup
			wg.Add(numKeys)

			b.StartTimer()
			for j := 0; j < numKeys; j++ {
				go func(keyID string) {
					defer wg.Done()
					_, err := km.Keyset(context.Background(), keyID)
					if err != nil {
						b.Errorf("Keyset failed during cache miss: %v", err)
					}
				}(keyIDs[j])
			}
			wg.Wait()
			b.StopTimer()
		}
	})

	// --- Sub-benchmark 2: Parallel Cache Hit (After Warmup) ---
	b.Run("ParallelHit_Cached", func(b *testing.B) {
		// Create and warm up a single key manager for this entire benchmark.
		km := setupBenchKeyManager(b, mock)
		for _, keyID := range keyIDs {
			// Pre-populate the cache before the benchmark starts.
			_, _ = km.Keyset(context.Background(), keyID)
		}

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			var wg sync.WaitGroup
			wg.Add(numKeys)
			for j := 0; j < numKeys; j++ {
				go func(keyID string) {
					defer wg.Done()
					_, err := km.Keyset(context.Background(), keyID)
					if err != nil {
						b.Errorf("Keyset failed during cache hit: %v", err)
					}
				}(keyIDs[j])
			}
			wg.Wait()
		}
	})
}
