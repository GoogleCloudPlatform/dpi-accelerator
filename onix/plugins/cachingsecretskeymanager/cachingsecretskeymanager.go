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

package cachingsecretskeymanager

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
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"

	"github.com/beckn/beckn-onix/pkg/model"
	plugin "github.com/beckn/beckn-onix/pkg/plugin/definition" // Plugin definitions will be imported from here.

	"github.com/google/uuid"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Config Required for the module.
type Config struct {
	ProjectID string
	SubscriberKeysCache bool
	NetworkKeysCache bool
}

type secretMgr interface {
	CreateSecret(context.Context, *secretmanagerpb.CreateSecretRequest, ...gax.CallOption) (*secretmanagerpb.Secret, error)
	AddSecretVersion(context.Context, *secretmanagerpb.AddSecretVersionRequest, ...gax.CallOption) (*secretmanagerpb.SecretVersion, error)
	DeleteSecret(context.Context, *secretmanagerpb.DeleteSecretRequest, ...gax.CallOption) error
	AccessSecretVersion(context.Context, *secretmanagerpb.AccessSecretVersionRequest, ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error)
	Close() error
}

type keyMgr struct {
	projectID                 string
	secretClient              secretMgr
	registry                  plugin.RegistryLookup
	cache                     plugin.Cache
	subscriberKeysCache       bool
	networkKeysCache          bool
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
func New(ctx context.Context, cache plugin.Cache, registryLookup plugin.RegistryLookup, cfg *Config) (*keyMgr, func() error, error) {
	secretClient, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create secret manager client: %w", err)
	}
	// Call the internal, testable constructor.
	return newWithClient(cache, registryLookup, cfg, secretClient)
}

// newWithClient is an internal constructor that accepts a secret manager client interface,
// making it easy to test with a mock client.
func newWithClient(cache plugin.Cache, registryLookup plugin.RegistryLookup, cfg *Config, client secretMgr) (*keyMgr, func() error, error) {
	if err := validateCfg(cfg); err != nil {
		return nil, nil, err
	}

	if registryLookup == nil {
		return nil, nil, ErrNilRegistryLookup
	}

	km := &keyMgr{
		projectID:            cfg.ProjectID,
		secretClient:         client,
		registry:             registryLookup,
		cache:                cache,
		subscriberKeysCache:  cfg.SubscriberKeysCache,
		networkKeysCache:     cfg.NetworkKeysCache,
	}

	return km, km.close, nil
}

// GenerateKeyset generates new signing and encryption key pairs.
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

// InsertKeyset stores keyset to the secret manager.
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

			// If deletion is successful we call the function again.
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

	if km.subscriberKeysCache {
		err = km.cache.Set(ctx, secretID, string(payload), time.Hour)
		if err != nil {
			// Log
		}
	}
	return nil
}

// Keyset fetches keyset from sercret manager.
func (km *keyMgr) Keyset(ctx context.Context, keyID string) (*model.Keyset, error) {
	if keyID == "" {
		return nil, model.NewBadReqErr(ErrEmptyKeyID)
	}

	secretID := generateSecretID(keyID)
	if km.subscriberKeysCache {
		cachedData, err := km.cache.Get(ctx, secretID)
		if err == nil {
			// Cache hit: keys are present in cache,so return the keys.
			var keyset *model.Keyset
			if err := json.Unmarshal([]byte(cachedData), &keyset); err == nil {
				return keyset, nil
			}
		}
	}
	secretName := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", km.projectID, secretID)
	res, err := km.secretClient.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: secretName,
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, model.NewBadReqErr(fmt.Errorf("keys for subscriberID: %s not found", keyID))
		}
		return nil, fmt.Errorf("failed to access secret version: %w", err)
	}

	if km.subscriberKeysCache {
		err = km.cache.Set(ctx, secretID, string(res.Payload.Data), time.Hour)
		if err != nil {
			// Log
		}
	}

	var keyset *model.Keyset
	if err := json.Unmarshal(res.Payload.Data, &keyset); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
	}
	return keyset, nil
}

// DeleteKeyset deletes the private keys from the secret manager.
func (km *keyMgr) DeleteKeyset(ctx context.Context, keyID string) error {
	if keyID == "" {
		return model.NewBadReqErr(ErrEmptyKeyID)
	}

	secretID := generateSecretID(keyID)
	secretName := fmt.Sprintf("projects/%s/secrets/%s", km.projectID, secretID)

	if km.subscriberKeysCache {
		err := km.cache.Delete(ctx, secretID)
		if err != nil {
			// Log
		}
	}

	if err := km.secretClient.DeleteSecret(ctx, &secretmanagerpb.DeleteSecretRequest{
		Name: secretName,
	}); err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}
	return nil
}

// LookupNPKeys fetches public keys from the registry or cache.
func (km *keyMgr) LookupNPKeys(ctx context.Context, subscriberID, uniqueKeyID string) (string, string, error) {
	if err := validateParams(subscriberID, uniqueKeyID); err != nil {
		return "", "", model.NewBadReqErr(err)
	}

	if km.networkKeysCache {
		// Check if the public keys corresponding to the subscriberID and uniqueKeyID are present in cache or not.
		cacheKey := fmt.Sprintf("%s_%s", subscriberID, uniqueKeyID)
		cachedData, err := km.cache.Get(ctx, cacheKey)
		if err == nil {
			// Cache hit: keys are present in cache,so return the keys.
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

	if km.networkKeysCache {
		cacheKey := fmt.Sprintf("%s_%s", subscriberID, uniqueKeyID)
		// Set fetched values in cache.
		cacheValue, err := json.Marshal(publicKeys)
		if err == nil {
			err := km.cache.Set(ctx, cacheKey, string(cacheValue), time.Hour)
			if err != nil {
				// Log
			}
		}
	}

	return publicKeys.SigningPublic, publicKeys.EncrPublic, nil
}

// close closes the connections.
func (km *keyMgr) close() error {
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
// It sanitizes the subscriber ID, hashes it, and combines them.
func generateSecretID(keyID string) string {
	// Sanitize the prefix.
	reg := regexp.MustCompile(invalidCharsRegex)
	sanitizedPrefix := reg.ReplaceAllString(keyID, "-")

	// Truncate if necessary, ensuring space for hash suffix and separator.
	if len(sanitizedPrefix) > maxPrefixLen {
		sanitizedPrefix = sanitizedPrefix[:maxPrefixLen]
	}

	// Generate SHA-256 hash of the original subscriberID.
	hash := sha256.Sum256([]byte(keyID))

	// Base64URL encode the hash.
	hashSuffix := encodeBase64URL(hash[:])

	secretID := fmt.Sprintf("%s_%s", sanitizedPrefix, hashSuffix)

	return secretID
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

// Error definitions.
var (
	ErrEmptyProjectID     = errors.New("invalid config: projectID cannot be empty")
	ErrNilCache           = errors.New("cache cannot be nil")
	ErrNilKeySet          = errors.New("keyset cannot be nil")
	ErrNilRegistryLookup  = errors.New("registry lookup cannot be nil")
	ErrEmptySubscriberID  = errors.New("subscriberID cannot be empty")
	ErrEmptyUniqueKeyID   = errors.New("uniqueKeyID cannot be empty")
	ErrEmptyKeyID         = errors.New("keyID cannot be empty")
	ErrSubscriberNotFound = errors.New("no subscriber found with given credentials")
)
