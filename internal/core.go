package internal

import (
	"errors"

	"github.com/doc-war/ckd/internal/siv"
)

const purposeKeyLen = 64 // AES-256-SIV 需要 64 字节密钥（32 S2V + 32 CTR）

// ErrInvalidDerivedKey 无效的派生密钥（解析失败时返回统一错误）
var ErrInvalidDerivedKey = errors.New("无效的派生密钥")

// ckd 是 CKD 协议的核心实现
type ckd struct {
	currentVersion   uint8
	secretsByVersion map[uint8][]byte
	cache            *purposeKeyCache
}

// New 创建 CKD 实例
func New(currentVersion uint8, secretsByVersion map[uint8][]byte) (*ckd, error) {
	if currentVersion < 1 || currentVersion > maxVersion {
		return nil, errors.New("当前版本号必须在 [1,15] 范围内")
	}
	if len(secretsByVersion) == 0 {
		return nil, errors.New("至少需要一个密钥版本")
	}
	for v := range secretsByVersion {
		if v < 1 || v > maxVersion {
			return nil, errors.New("密钥版本号必须在 [1,15] 范围内")
		}
		if len(secretsByVersion[v]) == 0 {
			return nil, errors.New("密钥不能为空")
		}
	}
	if _, ok := secretsByVersion[currentVersion]; !ok {
		return nil, errors.New("当前版本号对应的密钥不存在")
	}
	return &ckd{
		currentVersion:   currentVersion,
		secretsByVersion: secretsByVersion,
		cache:            newPurposeKeyCache(),
	}, nil
}

// Derive 从资源 ID 派生出外部标识 K
// resourceID: 内部资源标识（如 channel_id, user_id 等）
// purpose: 用途标识（如 "webhook", "sse", "api" 等）
// 返回: base64url 编码的派生密钥 K
func (c *ckd) Derive(resourceID []byte, purpose string) (string, error) {
	if len(resourceID) == 0 {
		return "", errors.New("资源 ID 不能为空")
	}
	if err := ValidatePurpose(purpose); err != nil {
		return "", err
	}

	secret := c.secretsByVersion[c.currentVersion]
	purposeKey := c.cache.get(c.currentVersion, purpose, secret)

	ciphertext, err := sivEncrypt(purposeKey, resourceID, []byte(purpose))
	if err != nil {
		return "", err
	}

	return Encode(c.currentVersion, ciphertext)
}

// Parse 从派生密钥 K 中恢复原始资源 ID
// derivedKey: base64url 编码的派生密钥
// purpose: 与派生时相同的用途标识
// 返回: 原始资源 ID
func (c *ckd) Parse(derivedKey string, purpose string) ([]byte, error) {
	if err := ValidatePurpose(purpose); err != nil {
		return nil, err
	}

	version, data, err := Decode(derivedKey)
	if err != nil {
		return nil, ErrInvalidDerivedKey
	}

	secret, ok := c.secretsByVersion[version]
	if !ok {
		return nil, ErrInvalidDerivedKey
	}

	purposeKey := c.cache.get(version, purpose, secret)

	plaintext, err := sivDecrypt(purposeKey, data, []byte(purpose))
	if err != nil {
		return nil, ErrInvalidDerivedKey
	}

	return plaintext, nil
}

// sivEncrypt 使用 AES-SIV 加密
// 返回: ciphertext || auth_tag（与 Go cipher.AEAD 约定一致）
func sivEncrypt(key, plaintext, aad []byte) ([]byte, error) {
	c, err := siv.New(key)
	if err != nil {
		return nil, err
	}
	return c.Seal(nil, nil, plaintext, aad), nil
}

// sivDecrypt 使用 AES-SIV 解密
// data: ciphertext || auth_tag（与 Go cipher.AEAD 约定一致）
func sivDecrypt(key, data, aad []byte) ([]byte, error) {
	c, err := siv.New(key)
	if err != nil {
		return nil, err
	}
	return c.Open(nil, nil, data, aad)
}
