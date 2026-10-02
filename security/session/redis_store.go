package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisStoreConfig defines configuration for distributed Redis sessions.
type RedisStoreConfig struct {
	Client    redis.UniversalClient
	KeyPrefix string // Defaults to "ztatic:session:"
	HashKey   bool   // If true, hashes session ID with SHA-256 for zero-trust storage
}

// RedisStore implements Store using Redis for high-throughput distributed sessions.
type RedisStore struct {
	client    redis.UniversalClient
	keyPrefix string
	hashKey   bool
}

// NewRedisStore creates a new distributed session store using a Redis UniversalClient.
func NewRedisStore(client redis.UniversalClient) *RedisStore {
	return NewRedisStoreWithConfig(RedisStoreConfig{
		Client:    client,
		KeyPrefix: "ztatic:session:",
		HashKey:   true,
	})
}

// NewRedisStoreWithConfig creates a RedisStore with custom settings.
func NewRedisStoreWithConfig(cfg RedisStoreConfig) *RedisStore {
	if cfg.KeyPrefix == "" {
		cfg.KeyPrefix = "ztatic:session:"
	}
	return &RedisStore{
		client:    cfg.Client,
		keyPrefix: cfg.KeyPrefix,
		hashKey:   cfg.HashKey,
	}
}

func (r *RedisStore) formatKey(id string) string {
	if r.hashKey {
		sum := sha256.Sum256([]byte(id))
		return r.keyPrefix + hex.EncodeToString(sum[:])
	}
	return r.keyPrefix + id
}

// Get retrieves and deserializes the session from Redis.
func (r *RedisStore) Get(ctx context.Context, id string) (*Session, error) {
	key := r.formatKey(id)
	data, err := r.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, ErrSessionNotFound
		}
		return nil, err
	}

	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}

	if time.Now().After(s.ExpiresAt) {
		_ = r.Destroy(ctx, id)
		return nil, ErrSessionExpired
	}

	s.isNew = false
	return &s, nil
}

// Save serializes and stores the session with an atomic Redis SETEX TTL.
func (r *RedisStore) Save(ctx context.Context, s *Session, ttl time.Duration) error {
	s.mu.RLock()
	s.ExpiresAt = time.Now().Add(ttl)
	data, err := json.Marshal(s)
	s.mu.RUnlock()

	if err != nil {
		return err
	}

	key := r.formatKey(s.ID)
	return r.client.Set(ctx, key, data, ttl).Err()
}

// Destroy immediately purges the session from Redis.
func (r *RedisStore) Destroy(ctx context.Context, id string) error {
	key := r.formatKey(id)
	return r.client.Del(ctx, key).Err()
}

// Touch extends the Redis key expiration without re-writing the session payload.
func (r *RedisStore) Touch(ctx context.Context, id string, ttl time.Duration) error {
	key := r.formatKey(id)
	ok, err := r.client.Expire(ctx, key, ttl).Result()
	if err != nil {
		return err
	}
	if !ok {
		return ErrSessionNotFound
	}
	return nil
}
