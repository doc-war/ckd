package ckd_test

import (
	"bytes"
	"testing"

	"github.com/doc-war/ckd"
)

// 测试密钥
var testSecret = []byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
}

// TestPublicAPI 验证公开 API 基本功能
func TestPublicAPI(t *testing.T) {
	c, err := ckd.New(ckd.Config{
		CurrentVersion: 1,
		SecretsByVersion: map[uint8][]byte{
			1: testSecret,
		},
	})
	if err != nil {
		t.Fatalf("创建 CKD 失败: %v", err)
	}

	resourceID := []byte("channel_12345")
	purpose := "webhook"

	key, err := c.Derive(resourceID, purpose)
	if err != nil {
		t.Fatalf("Derive 失败: %v", err)
	}

	got, err := c.Parse(key, purpose)
	if err != nil {
		t.Fatalf("Parse 失败: %v", err)
	}

	if !bytes.Equal(got, resourceID) {
		t.Fatalf("结果不匹配: got %v, want %v", got, resourceID)
	}
}

// TestPublicErrorTypes 验证错误类型可被调用方识别
func TestPublicErrorTypes(t *testing.T) {
	c, err := ckd.New(ckd.Config{
		CurrentVersion: 1,
		SecretsByVersion: map[uint8][]byte{
			1: testSecret,
		},
	})
	if err != nil {
		t.Fatalf("创建 CKD 失败: %v", err)
	}

	// 非法 purpose
	if _, err := c.Derive([]byte("test"), "BadPurpose"); err != ckd.ErrInvalidPurpose {
		t.Fatalf("期望 ErrInvalidPurpose, 得到 %v", err)
	}

	// 无效密钥
	if _, err := c.Parse("!!!!", "webhook"); err != ckd.ErrInvalidDerivedKey {
		t.Fatalf("期望 ErrInvalidDerivedKey, 得到 %v", err)
	}
}

// TestPublicMultiVersion 验证公开 API 多版本
func TestPublicMultiVersion(t *testing.T) {
	secrets := map[uint8][]byte{
		1: testSecret,
		2: {
			0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
			0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
			0xef, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9, 0xe8,
			0xe7, 0xe6, 0xe5, 0xe4, 0xe3, 0xe2, 0xe1, 0xe0,
		},
	}

	ckd1, err := ckd.New(ckd.Config{CurrentVersion: 1, SecretsByVersion: secrets})
	if err != nil {
		t.Fatalf("创建 CKD(v1) 失败: %v", err)
	}

	key, err := ckd1.Derive([]byte("test"), "webhook")
	if err != nil {
		t.Fatalf("Derive(v1) 失败: %v", err)
	}

	// v2 实例能解析 v1 的 key（因为 secrets 包含 v1）
	ckd2, err := ckd.New(ckd.Config{CurrentVersion: 2, SecretsByVersion: secrets})
	if err != nil {
		t.Fatalf("创建 CKD(v2) 失败: %v", err)
	}

	got, err := ckd2.Parse(key, "webhook")
	if err != nil {
		t.Fatalf("v2 Parse v1 key 失败: %v", err)
	}
	if !bytes.Equal(got, []byte("test")) {
		t.Fatalf("结果不匹配")
	}
}

// TestPublicInvalidConfig 验证无效配置被拒绝
func TestPublicInvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  ckd.Config
	}{
		{"版本号 0", ckd.Config{CurrentVersion: 0, SecretsByVersion: map[uint8][]byte{0: testSecret}}},
		{"版本号 16", ckd.Config{CurrentVersion: 16, SecretsByVersion: map[uint8][]byte{16: testSecret}}},
		{"空密钥表", ckd.Config{CurrentVersion: 1, SecretsByVersion: map[uint8][]byte{}}},
		{"版本不匹配", ckd.Config{CurrentVersion: 1, SecretsByVersion: map[uint8][]byte{2: testSecret}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ckd.New(tt.cfg); err == nil {
				t.Fatal("无效配置应被拒绝")
			}
		})
	}
}
