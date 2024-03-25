package session

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"

	util "github.com/argoproj/argo-cd/v2/util/io"
)

const (
	revokedTokenPrefix = "revoked-token|"
	newRevokedTokenKey = "new-revoked-token"
)

type userStateStorage struct {
	attempts       map[string]LoginAttempts
	redis          *redis.Client
	revokedTokens  map[string]bool
	lock           sync.RWMutex
	resyncDuration time.Duration
}

var _ UserStateStorage = &userStateStorage{}

func NewUserStateStorage(redis *redis.Client) *userStateStorage {
	return &userStateStorage{
		attempts:       map[string]LoginAttempts{},
		revokedTokens:  map[string]bool{},
		resyncDuration: time.Hour,
		redis:          redis,
	}
}

func (storage *userStateStorage) Init(ctx context.Context) {
	go storage.watchRevokedTokens(ctx)
	ticker := time.NewTicker(storage.resyncDuration)
	go func() {
		storage.loadRevokedTokensSafe()
		for range ticker.C {
			storage.loadRevokedTokensSafe()
		}
	}()
	go func() {
		<-ctx.Done()
		ticker.Stop()
	}()
}

func (storage *userStateStorage) watchRevokedTokens(ctx context.Context) {
	pubsub := storage.redis.Subscribe(ctx, newRevokedTokenKey)
	defer util.Close(pubsub)

	ch := pubsub.Channel()
	for {
		select {
		case <-ctx.Done():
			return
		case val := <-ch:
			storage.lock.Lock()
			storage.revokedTokens[val.Payload] = true
			storage.lock.Unlock()
		}
	}
}

func (storage *userStateStorage) loadRevokedTokensSafe() {
	err := storage.loadRevokedTokens()
	for err != nil {
		log.Warnf("Failed to resync revoked tokens. retrying again in 1 minute: %v", err)
		time.Sleep(time.Minute)
		err = storage.loadRevokedTokens()
	}
}

func (storage *userStateStorage) loadRevokedTokens() error {
	log.Infof("!!! loadRevokedTokens attempting Lock !!!")
	storage.lock.Lock()
	log.Infof("!!! loadRevokedTokens successful Lock !!!")
	defer storage.UnlockLog("!!! loadRevokedTokens Unlock called !!!")
	storage.revokedTokens = map[string]bool{}
	iterator := storage.redis.Scan(context.Background(), 0, revokedTokenPrefix+"*", -1).Iterator()
	for iterator.Next(context.Background()) {
		parts := strings.Split(iterator.Val(), "|")
		if len(parts) != 2 {
			log.Warnf("Unexpected redis key prefixed with '%s'. Must have token id after the prefix but got: '%s'.",
				revokedTokenPrefix,
				iterator.Val())
			continue
		}
		storage.revokedTokens[parts[1]] = true
	}
	if iterator.Err() != nil {
		return iterator.Err()
	}

	return nil
}

func (storage *userStateStorage) GetLoginAttempts(attempts *map[string]LoginAttempts) error {
	*attempts = storage.attempts
	return nil
}

func (storage *userStateStorage) SetLoginAttempts(attempts map[string]LoginAttempts) error {
	storage.attempts = attempts
	return nil
}

func (storage *userStateStorage) RevokeToken(ctx context.Context, id string, expiringAt time.Duration) error {
	log.Infof("!!! RevokeToken attempting Lock !!!")
	storage.lock.Lock()
	log.Infof("!!! RevokeToken successful Lock !!!")
	storage.revokedTokens[id] = true
	storage.lock.Unlock()
	log.Infof("!!! RevokeToken successful Unlock !!!")
	if err := storage.redis.Set(ctx, revokedTokenPrefix+id, "", expiringAt).Err(); err != nil {
		return err
	}
	return storage.redis.Publish(ctx, newRevokedTokenKey, id).Err()
}

func (storage *userStateStorage) RUnlockLog(message string) {
	storage.lock.RUnlock()
	log.Infof(message)
}

func (storage *userStateStorage) UnlockLog(message string) {
	storage.lock.Unlock()
	log.Infof(message)
}

func (storage *userStateStorage) IsTokenRevoked(id string) bool {
	log.Infof("!!! IsTokenRevoked attempting RLock !!!")
	storage.lock.RLock()
	log.Infof("!!! IsTokenRevoked successful RLock !!!")
	defer storage.RUnlockLog("!!! IsTokenRevoked RUnlock called !!!")
	return storage.revokedTokens[id]
}

type UserStateStorage interface {
	Init(ctx context.Context)
	// GetLoginAttempts return number of concurrent login attempts
	GetLoginAttempts(attempts *map[string]LoginAttempts) error
	// SetLoginAttempts sets number of concurrent login attempts
	SetLoginAttempts(attempts map[string]LoginAttempts) error
	// RevokeToken revokes token with given id (information about revocation expires after specified timeout)
	RevokeToken(ctx context.Context, id string, expiringAt time.Duration) error
	// IsTokenRevoked checks if given token is revoked
	IsTokenRevoked(id string) bool
}
