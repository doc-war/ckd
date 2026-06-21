package internal

import (
	"fmt"
	"sync"
)

// purposeKeyCache 缓存在 (version, purpose) 下计算的 PurposeKey
// 避免每次 Derive/Parse 都重新计算 HKDF
type purposeKeyCache struct {
	mu    sync.RWMutex
	items map[string][]byte
}

func newPurposeKeyCache() *purposeKeyCache {
	return &purposeKeyCache{
		items: make(map[string][]byte),
	}
}

// get 获取缓存的 PurposeKey，未命中则计算并缓存
func (c *purposeKeyCache) get(version uint8, purpose string, secret []byte) []byte {
	key := cacheKey(version, purpose)

	c.mu.RLock()
	if pk, ok := c.items[key]; ok {
		c.mu.RUnlock()
		return pk
	}
	c.mu.RUnlock()

	pk := derivePurposeKey(secret, purpose)

	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.items[key]; ok {
		return existing
	}
	c.items[key] = pk
	return pk
}

func cacheKey(version uint8, purpose string) string {
	return fmt.Sprintf("%d:%s", version, purpose)
}
