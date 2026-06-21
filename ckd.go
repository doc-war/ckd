// Package ckd 实现 CKD（Channel Key Derivation）通道密钥派生算法
//
// CKD 是一种轻量级、无状态、可逆的资源标识派生协议。
// 它允许从一个内部资源标识派生出多个不同用途的外部标识，
// 并支持在不依赖映射表的情况下恢复原始资源标识。
//
// 核心特性：
//   - 用途隔离：不同用途的派生密钥不可互相推导
//   - 无状态：无需存储 K→C 映射关系
//   - 可逆：支持从派生密钥恢复原始资源 ID
//   - 多版本：支持密钥平滑轮换
//
// 使用示例：
//
//	ckd, err := ckd.New(ckd.Config{
//	    CurrentVersion: 1,
//	    SecretsByVersion: map[uint8][]byte{
//	        1: masterSecret,
//	    },
//	})
//	key, err := ckd.Derive(channelID, "webhook")
//	id, err := ckd.Parse(key, "webhook")
package ckd

import (
	"github.com/doc-war/ckd/internal"
)

// CKD 是 CKD 协议的核心接口
type CKD interface {
	// Derive 从资源 ID 派生出外部标识 K
	//   resourceID: 内部资源标识（如 channel_id, user_id 等）
	//   purpose: 用途标识（如 "webhook", "sse", "api" 等）
	//   返回: base64url 编码的派生密钥 K
	Derive(resourceID []byte, purpose string) (string, error)

	// Parse 从派生密钥 K 中恢复原始资源 ID
	//   derivedKey: base64url 编码的派生密钥
	//   purpose: 与派生时相同的用途标识
	//   返回: 原始资源 ID
	Parse(derivedKey string, purpose string) ([]byte, error)
}

// Config 是创建 CKD 实例的配置
type Config struct {
	// CurrentVersion 当前生效的密钥版本号，取值范围 [1,15]
	CurrentVersion uint8

	// SecretsByVersion 多版本密钥映射表
	// key 为版本号 [1,15]，value 为对应密钥（建议 ≥ 32 字节）
	SecretsByVersion map[uint8][]byte
}

var (
	// ErrInvalidPurpose 用途标识格式无效
	ErrInvalidPurpose = internal.ErrInvalidPurpose
	// ErrInvalidDerivedKey 派生密钥无效（解析失败）
	ErrInvalidDerivedKey = internal.ErrInvalidDerivedKey
)

// New 创建 CKD 实例
func New(cfg Config) (CKD, error) {
	return internal.New(cfg.CurrentVersion, cfg.SecretsByVersion)
}
