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
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"

	"github.com/beckn/beckn-onix/pkg/model"
	plugin "github.com/beckn/beckn-onix/pkg/plugin/definition"

	"github.com/google/uuid"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Error definitions.
var (
	ErrEmptyProjectID     = errors.New("invalid config: projectID cannot be empty")
	ErrInvalidTTL         = errors.New("invalid config: TTL values must be positive")
	ErrNilKeySet          = errors.New("keyset cannot be nil")
	ErrNilRegistryLookup  = errors.New("registry lookup cannot be nil")
	ErrEmptySubscriberID  = errors.New("subscriberID cannot be empty")
	ErrEmptyUniqueKeyID   = errors.New("uniqueKeyID cannot be empty")
	ErrEmptyKeyID         = errors.New("keyID cannot be empty")
	ErrSubscriberNotFound = errors.New("no subscriber found with given credentials")
)

// CacheTTL holds the TTL configuration for different key types in seconds.
type CacheTTL struct {
	PrivateKeysSeconds int `yaml:"privateKeysSeconds"`
	PublicKeysSeconds  int `yaml:"publicKeysSeconds"`
}

type inFlightRequest struct {
	done   chan struct{}
	result fetchResult
}

type fetchResult struct {
    keyset *model.Keyset
    err    error
}

// Config holds the configuration for the key manager.
type Config struct {
	ProjectID string
	CacheTTL  CacheTTL
}

// inMemoryCacheItem holds the cached data and its expiration time.
type inMemoryCacheItem struct {
	keyset    *model.Keyset
	expiresAt time.Time
}

type inMemoryCache struct {
	sync.RWMutex
	items map[string]inMemoryCacheItem
	ttl   time.Duration
}

// Get retrieves an item from the cache. returns the item and a boolean indicating if it was found and not expired.
func (c *inMemoryCache) Get(key string) (*model.Keyset, bool) {
	c.RLock()
	defer c.RUnlock()
	item, found := c.items[key]
	if !found || time.Now().After(item.expiresAt) {
		return nil, false
	}
	return item.keyset, true
}

// Set adds an item to the cache with the configured TTL.
func (c *inMemoryCache) Set(key string, keyset *model.Keyset) {
	c.Lock()
	defer c.Unlock()
	c.items[key] = inMemoryCacheItem{
		keyset:    keyset,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// Delete removes an item from the cache.
func (c *inMemoryCache) Delete(key string) {
	c.Lock()
	defer c.Unlock()

	// Securely wipe the keyset before deleting the map entry
	if item, found := c.items[key]; found {
		if item.keyset != nil {
			securelyWipeKeyset(item.keyset)
		}
	}

	delete(c.items, key)
}

type secretMgr interface {
	CreateSecret(context.Context, *secretmanagerpb.CreateSecretRequest, ...gax.CallOption) (*secretmanagerpb.Secret, error)
	AddSecretVersion(context.Context, *secretmanagerpb.AddSecretVersionRequest, ...gax.CallOption) (*secretmanagerpb.SecretVersion, error)
	DeleteSecret(context.Context, *secretmanagerpb.DeleteSecretRequest, ...gax.CallOption) error
	AccessSecretVersion(context.Context, *secretmanagerpb.AccessSecretVersionRequest, ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error)
	Close() error
}

type keyMgr struct {
	projectID         string
	secretClient      secretMgr
	registry          plugin.RegistryLookup
	redisCache        plugin.Cache
	inMemoryCache     *inMemoryCache
	publicKeyCacheTTL time.Duration
	requestMutex sync.Mutex
    requests     map[string]*inFlightRequest
}

// Constants for secret ID generation.
const (
	maxSecretIDLen = 255
	hashSuffixLen  = 43 // SHA-256 (32 bytes) base64url encoded, no padding.
	// Max prefix length ensures (prefix + separator + hash) <= maxSecretIDLen.
	maxPrefixLen      = maxSecretIDLen - hashSuffixLen - 1 // -1 for the separator char
	invalidCharsRegex = `[^a-zA-Z0-9_-]+`                  // Matches anything not alphanumeric, underscore, or hyphen.
)

// New method creates a new KeyManager instance.
func New(ctx context.Context, redisCache plugin.Cache, registryLookup plugin.RegistryLookup, cfg *Config) (*keyMgr, func() error, error) {
	secretClient, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create secret manager client: %w", err)
	}
	return newWithClient(redisCache, registryLookup, cfg, secretClient)
}

func newWithClient(redisCache plugin.Cache, registryLookup plugin.RegistryLookup, cfg *Config, client secretMgr) (*keyMgr, func() error, error) {
	if err := validateCfg(cfg); err != nil {
		return nil, nil, err
	}

	if registryLookup == nil {
		return nil, nil, ErrNilRegistryLookup
	}

	privateKeyTTL := time.Duration(cfg.CacheTTL.PrivateKeysSeconds) * time.Second
	inMemCache := &inMemoryCache{
		items: make(map[string]inMemoryCacheItem),
		ttl:   privateKeyTTL,
	}

	km := &keyMgr{
		projectID:         cfg.ProjectID,
		secretClient:      client,
		registry:          registryLookup,
		redisCache:        redisCache,
		inMemoryCache:     inMemCache,
		publicKeyCacheTTL: time.Duration(cfg.CacheTTL.PublicKeysSeconds) * time.Second,
		requests:          make(map[string]*inFlightRequest),
	}

	return km, km.close, nil
}




// generates new signing and encryption key pairs.
func (km *keyMgr) GenerateKeyset() (*model.Keyset, error) {
	// Generate Signing keys.
	signingPublic, signingPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate signing key pair: %w", err)
	}

	// Generate x25519 Keys.
	encrPrivateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate encryption key pair: %w", err)
	}

	encrPublicKey := encrPrivateKey.PublicKey().Bytes()

	// Generate uuid for UniqueKeyID.
	uuid, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate unique key id uuid: %w", err)
	}

	return &model.Keyset{
		UniqueKeyID:    uuid.String(),
		SigningPrivate: encodeBase64(signingPrivate.Seed()),
		SigningPublic:  encodeBase64(signingPublic),
		EncrPrivate:    encodeBase64(encrPrivateKey.Bytes()),
		EncrPublic:     encodeBase64(encrPublicKey),
	}, nil
}

// InsertKeyset stores keyset to the secret manager and caches it in-memory.
func (km *keyMgr) InsertKeyset(ctx context.Context, keyID string, keyset *model.Keyset) error {
	if keyID == "" {
		return model.NewBadReqErr(ErrEmptyKeyID)
	}
	if keyset == nil {
		return model.NewBadReqErr(ErrNilKeySet)
	}

	secretID := generateSecretID(keyID)
	secretName := fmt.Sprintf("projects/%s/secrets/%s", km.projectID, secretID)

	// Create secret.
	_, err := km.secretClient.CreateSecret(ctx, &secretmanagerpb.CreateSecretRequest{
		Parent:   fmt.Sprintf("projects/%s", km.projectID),
		SecretId: secretID,
		Secret: &secretmanagerpb.Secret{
			Replication: &secretmanagerpb.Replication{
				Replication: &secretmanagerpb.Replication_Automatic_{
					Automatic: &secretmanagerpb.Replication_Automatic{},
				},
			},
		},
	})

	if err != nil {
		// check for already exists error.
		if status.Code(err) == codes.AlreadyExists {
			// Delete existing secret with same keyID.
			if err := km.DeleteKeyset(ctx, keyID); err != nil {
				return fmt.Errorf("failed to delete existing secret with same keyID: %w", err)
			}

			return km.InsertKeyset(ctx, keyID, keyset)
		}
		return fmt.Errorf("failed to create secret: %w", err)
	}
	payload, err := json.Marshal(keyset)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Store the secret.
	_, err = km.secretClient.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
		Parent:  secretName,
		Payload: &secretmanagerpb.SecretPayload{Data: payload},
	})
	if err != nil {
		return fmt.Errorf("failed to add secret version: %w", err)
	}

	// Add to in-memory cache
	km.inMemoryCache.Set(secretID, keyset)

	return nil
}

// Keyset fetches keyset from in-memory cache or using a channel-based mechanism to prevent thundering herds from secret manager.
func (km *keyMgr) Keyset(ctx context.Context, keyID string) (*model.Keyset, error) {
	// Step 1: Validate the input keyID to ensure it's not empty.
	if keyID == "" {
		return nil, model.NewBadReqErr(ErrEmptyKeyID)
	}
	secretID := generateSecretID(keyID)

	// Step 2: Check the in-memory cache first (the fast path).
	if keyset, found := km.inMemoryCache.Get(secretID); found {
		return keyset, nil
	}

	// --- Begin Thundering Herd Prevention ---
	// The following logic ensures that if multiple concurrent requests are made for the
	// same missing key, only one request ("the leader") will fetch it from the backend.
	// All other requests ("the followers") will wait for the leader's result.

	// Step 3: Lock the mutex to safely access the shared 'requests' map.
	km.requestMutex.Lock()
	req, found := km.requests[secretID]
	if found {
		// Step 4a (Follower Path): A request is already in-flight.
		// Unlock the mutex immediately and wait for the leader to finish.
		km.requestMutex.Unlock()
		<-req.done // Block until the 'done' channel is closed by the leader.
		return req.result.keyset, req.result.err
	}

	// Step 4b (Leader Path): No request is in-flight. This goroutine becomes the leader.
	// Create a new request tracker for other goroutines to find and unlock the mutex.
	req = &inFlightRequest{
		done: make(chan struct{}),
	}
	km.requests[secretID] = req
	km.requestMutex.Unlock()

	// Step 5 (Leader): Defer the broadcast and cleanup.
	defer func() {
		km.requestMutex.Lock()
		delete(km.requests, secretID)
		km.requestMutex.Unlock()
		close(req.done)
	}()

	// Step 6 (Leader): Perform the actual fetch from the secret manager backend and process it.
	secretName := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", km.projectID, secretID)
	res, err := km.secretClient.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: secretName,
	})

	var fetchedKeyset *model.Keyset
	if err != nil {
		if status.Code(err) == codes.NotFound {
			err = model.NewBadReqErr(fmt.Errorf("keys for subscriberID: %s not found", keyID))
		} else {
			err = fmt.Errorf("failed to access secret version: %w", err)
		}
	} else {
		if err = json.Unmarshal(res.Payload.Data, &fetchedKeyset); err != nil {
			err = fmt.Errorf("failed to unmarshal payload: %w", err)
		} else {
			// Step 7 (Leader): If unmarshaling is successful, populate the in-memory cache.
			km.inMemoryCache.Set(secretID, fetchedKeyset)
		}
	}

	// Step 9 (Leader): Store the final result (either the keyset or an error) in the shared request struct
	req.result = fetchResult{keyset: fetchedKeyset, err: err}

	return req.result.keyset, req.result.err
}

// DeleteKeyset deletes the private keys from the secret manager and the in-memory cache.
func (km *keyMgr) DeleteKeyset(ctx context.Context, keyID string) error {
	if keyID == "" {
		return model.NewBadReqErr(ErrEmptyKeyID)
	}

	secretID := generateSecretID(keyID)
	secretName := fmt.Sprintf("projects/%s/secrets/%s", km.projectID, secretID)

	// Delete from in-memory cache first.
	km.inMemoryCache.Delete(secretID)

	// Then delete from secret manager.
	if err := km.secretClient.DeleteSecret(ctx, &secretmanagerpb.DeleteSecretRequest{
		Name: secretName,
	}); err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}
	return nil
}

// LookupNPKeys fetches public keys from the Redis cache or registry.
func (km *keyMgr) LookupNPKeys(ctx context.Context, subscriberID, uniqueKeyID string) (string, string, error) {
	if err := validateParams(subscriberID, uniqueKeyID); err != nil {
		return "", "", model.NewBadReqErr(err)
	}

	// If a redis cache is provided, use it.
	if km.redisCache != nil {
		// Check if the public keys are present in the provided Redis cache.
		cacheKey := fmt.Sprintf("%s_%s", subscriberID, uniqueKeyID)
		cachedData, err := km.redisCache.Get(ctx, cacheKey)
		if err == nil {
			// Cache hit: keys are present in cache, so return the keys.
			var keys *model.Keyset
			if err := json.Unmarshal([]byte(cachedData), &keys); err == nil {
				return keys.SigningPublic, keys.EncrPublic, nil
			}
		}
	}

	// fetch from registry.
	publicKeys, err := km.lookupRegistry(ctx, subscriberID, uniqueKeyID)
	if err != nil {
		return "", "", err
	}

	// If a redis cache is provided, set the fetched values in it.
	if km.redisCache != nil {
		cacheKey := fmt.Sprintf("%s_%s", subscriberID, uniqueKeyID)
		// Set fetched values in Redis cache.
		cacheValue, err := json.Marshal(publicKeys)
		if err == nil {
			_ = km.redisCache.Set(ctx, cacheKey, string(cacheValue), km.publicKeyCacheTTL)
		}
	}

	return publicKeys.SigningPublic, publicKeys.EncrPublic, nil
}

// close closes the connections.
func (km *keyMgr) close() error {
	km.securelyWipeAndClearCache()
	return km.secretClient.Close()
}

// encodeBase64 encodes byte data to base64.
func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// encodeBase64URL encodes byte data to base64url.
func encodeBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// generateSecretID creates a Secret Manager compatible secret ID from a subscriber ID.
func generateSecretID(keyID string) string {
	reg := regexp.MustCompile(invalidCharsRegex)
	sanitizedPrefix := reg.ReplaceAllString(keyID, "-")

	if len(sanitizedPrefix) > maxPrefixLen {
		sanitizedPrefix = sanitizedPrefix[:maxPrefixLen]
	}

	hash := sha256.Sum256([]byte(keyID))
	hashSuffix := encodeBase64URL(hash[:])

	return fmt.Sprintf("%s_%s", sanitizedPrefix, hashSuffix)
}

// lookupRegistry makes the lookup call to registry using registryLookup implementation.
func (km *keyMgr) lookupRegistry(ctx context.Context, subscriberID, uniqueKeyID string) (*model.Keyset, error) {
	subscribers, err := km.registry.Lookup(ctx, &model.Subscription{
		Subscriber: model.Subscriber{
			SubscriberID: subscriberID,
		},
		KeyID: uniqueKeyID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to lookup registry: %w", err)
	}

	if len(subscribers) == 0 {
		return nil, model.NewBadReqErr(ErrSubscriberNotFound)
	}
	return &model.Keyset{
		SigningPublic: subscribers[0].SigningPublicKey,
		EncrPublic:    subscribers[0].EncrPublicKey,
	}, nil
}

// validateCfg validates the config.
func validateCfg(cfg *Config) error {
	if cfg.ProjectID == "" {
		return ErrEmptyProjectID
	}
	if cfg.CacheTTL.PrivateKeysSeconds <= 0 || cfg.CacheTTL.PublicKeysSeconds <= 0 {
		return ErrInvalidTTL
	}
	return nil
}

func validateParams(subscriberID, uniqueKeyID string) error {
	if subscriberID == "" {
		return ErrEmptySubscriberID
	}
	if uniqueKeyID == "" {
		return ErrEmptyUniqueKeyID
	}
	return nil
}


// securelyWipeKeyset overwrites the private key data within the Keyset with zeros
// to prevent sensitive information from being recovered from memory.
func securelyWipeKeyset(ks *model.Keyset) {
	if ks == nil {
		return
	}
	// Helper function to securely wipe a byte slice
	zeroBytes := func(b []byte) {
		for i := range b {
			b[i] = 0
		}
	}

	// Decode from base64 and wipe the resulting byte slice
	if signingBytes, err := base64.StdEncoding.DecodeString(ks.SigningPrivate); err == nil {
		zeroBytes(signingBytes)
	}
	if encrBytes, err := base64.StdEncoding.DecodeString(ks.EncrPrivate); err == nil {
		zeroBytes(encrBytes)
	}

	// Set strings to empty to be safe
	ks.SigningPrivate = ""
	ks.EncrPrivate = ""
}

// securelyWipeAndClearCache iterates through the cache, wipes each keyset, and clears the map.
func (km *keyMgr) securelyWipeAndClearCache() {
	km.inMemoryCache.Lock()
	defer km.inMemoryCache.Unlock()

	for key, item := range km.inMemoryCache.items {
		if item.keyset != nil {
			securelyWipeKeyset(item.keyset)
		}
		delete(km.inMemoryCache.items, key)
	}
}


