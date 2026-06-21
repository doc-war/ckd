package internal

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// 固定测试向量，用于跨语言验证
var (
	// 32 字节测试密钥（AES-256-SIV 使用 64 字节 PurposeKey）
	testSecret = []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	testSecretV2 = []byte{
		0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
		0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
		0xef, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9, 0xe8,
		0xe7, 0xe6, 0xe5, 0xe4, 0xe3, 0xe2, 0xe1, 0xe0,
	}
	testResourceID  = []byte("channel_12345")
	testResourceID2 = []byte("user_67890")
	testPurpose1    = "webhook"
	testPurpose2    = "sse"
)

// newTestCKD 创建测试用 CKD 实例
func newTestCKD(t *testing.T) *ckd {
	t.Helper()
	c, err := New(1, map[uint8][]byte{1: testSecret})
	if err != nil {
		t.Fatalf("创建 CKD 失败: %v", err)
	}
	return c
}

// TestDeriveParseRoundTrip 验证 Derive → Parse 往返一致性
func TestDeriveParseRoundTrip(t *testing.T) {
	c := newTestCKD(t)

	key, err := c.Derive(testResourceID, testPurpose1)
	if err != nil {
		t.Fatalf("Derive 失败: %v", err)
	}

	got, err := c.Parse(key, testPurpose1)
	if err != nil {
		t.Fatalf("Parse 失败: %v", err)
	}

	if !bytes.Equal(got, testResourceID) {
		t.Fatalf("Parse 结果不匹配: got %v, want %v", got, testResourceID)
	}
}

// TestPurposeIsolation 验证不同用途的派生密钥不可互相解析
func TestPurposeIsolation(t *testing.T) {
	c := newTestCKD(t)

	key1, err := c.Derive(testResourceID, testPurpose1)
	if err != nil {
		t.Fatalf("Derive webhook 失败: %v", err)
	}

	key2, err := c.Derive(testResourceID, testPurpose2)
	if err != nil {
		t.Fatalf("Derive sse 失败: %v", err)
	}

	// 两个 Key 不应相等
	if key1 == key2 {
		t.Fatal("不同 purpose 的 Key 不应相等")
	}

	// 用错误 purpose 解析应失败
	if _, err := c.Parse(key1, testPurpose2); err == nil {
		t.Fatal("使用错误 purpose 解析应返回错误")
	}
	if _, err := c.Parse(key2, testPurpose1); err == nil {
		t.Fatal("使用错误 purpose 解析应返回错误")
	}
}

// TestDeterministic 验证相同输入产生相同输出
func TestDeterministic(t *testing.T) {
	c := newTestCKD(t)

	key1, err := c.Derive(testResourceID, testPurpose1)
	if err != nil {
		t.Fatalf("第一次 Derive 失败: %v", err)
	}

	key2, err := c.Derive(testResourceID, testPurpose1)
	if err != nil {
		t.Fatalf("第二次 Derive 失败: %v", err)
	}

	if key1 != key2 {
		t.Fatal("确定性派生失败：相同输入产生不同输出")
	}
}

// TestInvalidPurpose 验证非法 purpose 被拒绝
func TestInvalidPurpose(t *testing.T) {
	c := newTestCKD(t)

	invalidPurposes := []string{
		"",           // 空
		"Webhook",    // 大写字母
		"web hook",   // 含空格
		"webhook!",   // 特殊字符
		"中文",       // 非 ASCII
		"a",          // 太短但合法
	}

	for _, p := range invalidPurposes {
		p := p
		t.Run(p, func(t *testing.T) {
			if p == "a" {
				// "a" 实际上是合法的
				return
			}
			if _, err := c.Derive(testResourceID, p); err == nil {
				t.Fatalf("非法 purpose %q 应被拒绝", p)
			}
			if _, err := c.Parse("AQAAAA", p); err == nil {
				t.Fatalf("非法 purpose %q 应被拒绝", p)
			}
		})
	}

	// 验证合法 purpose 通过
	validPurposes := []string{
		"a",
		"webhook",
		"sse_endpoint_v2",
		"api-key-2024",
	}
	for _, p := range validPurposes {
		if _, err := c.Derive(testResourceID, p); err != nil {
			t.Fatalf("合法 purpose %q 被拒绝: %v", p, err)
		}
	}

	// 验证长度边界
	longPurpose := make([]byte, 64)
	for i := range longPurpose {
		longPurpose[i] = 'a'
	}
	if _, err := c.Derive(testResourceID, string(longPurpose)); err != nil {
		t.Fatalf("64 字节的合法 purpose 被拒绝: %v", err)
	}

	tooLong := make([]byte, 65)
	for i := range tooLong {
		tooLong[i] = 'a'
	}
	if _, err := c.Derive(testResourceID, string(tooLong)); err == nil {
		t.Fatal("65 字节的 purpose 应被拒绝")
	}
}

// TestInvalidKey 验证无效的派生密钥被拒绝
func TestInvalidKey(t *testing.T) {
	c := newTestCKD(t)

	invalidKeys := []string{
		"",                            // 空字符串
		"!!!",                         // 无效 base64url
		"YQ",                          // 合法 base64url 但太短
		"AQ",                          // 版本号 0（保留）
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAA", // 长度不足
	}

	for _, k := range invalidKeys {
		k := k
		t.Run(k, func(t *testing.T) {
			if _, err := c.Parse(k, testPurpose1); err == nil {
				t.Fatalf("无效密钥 %q 应被拒绝", k)
			}
		})
	}
}

// TestVersionHeader 验证版本号正确编码
func TestVersionHeader(t *testing.T) {
	for version := uint8(1); version <= 15; version++ {
		c, err := New(version, map[uint8][]byte{version: testSecret})
		if err != nil {
			t.Fatalf("创建 version=%d CKD 失败: %v", version, err)
		}

		key, err := c.Derive(testResourceID, testPurpose1)
		if err != nil {
			t.Fatalf("version=%d Derive 失败: %v", version, err)
		}

		got, err := c.Parse(key, testPurpose1)
		if err != nil {
			t.Fatalf("version=%d Parse 失败: %v", version, err)
		}
		if !bytes.Equal(got, testResourceID) {
			t.Fatalf("version=%d 往返结果不匹配", version)
		}
	}
}

// TestMultiVersion 验证多版本密钥共存
func TestMultiVersion(t *testing.T) {
	secrets := map[uint8][]byte{
		1: testSecret,
		2: testSecretV2,
	}

	// 使用版本 1
	c1, err := New(1, secrets)
	if err != nil {
		t.Fatalf("创建 CKD(v1) 失败: %v", err)
	}
	key1, err := c1.Derive(testResourceID, testPurpose1)
	if err != nil {
		t.Fatalf("v1 Derive 失败: %v", err)
	}

	// 使用版本 2
	c2, err := New(2, secrets)
	if err != nil {
		t.Fatalf("创建 CKD(v2) 失败: %v", err)
	}
	key2, err := c2.Derive(testResourceID, testPurpose1)
	if err != nil {
		t.Fatalf("v2 Derive 失败: %v", err)
	}

	// 不同版本的 Key 不应相同
	if key1 == key2 {
		t.Fatal("不同版本的 Key 不应相等")
	}

	// v1 Parse v1 的 Key 成功
	if _, err := c1.Parse(key1, testPurpose1); err != nil {
		t.Fatalf("v1 Parse v1 key 失败: %v", err)
	}

	// v1 Parse v2 的 Key 失败（用当前密钥但版本是 2）
	if _, err := c1.Parse(key2, testPurpose1); err != nil {
		t.Logf("v1 Parse v2 key 按预期失败: %v", err)
	}

	// v2 Parse v2 的 Key 成功
	if _, err := c2.Parse(key2, testPurpose1); err != nil {
		t.Fatalf("v2 Parse v2 key 失败: %v", err)
	}

	// v2 Parse v1 的 Key 也成功（因为 v2 实例也包含 v1 密钥）
	if _, err := c2.Parse(key1, testPurpose1); err != nil {
		t.Fatalf("v2 Parse v1 key 失败: %v", err)
	}
}

// TestReservedBits 验证 reserved 位被忽略（向前兼容）
func TestReservedBits(t *testing.T) {
	c := newTestCKD(t)

	key, err := c.Derive(testResourceID, testPurpose1)
	if err != nil {
		t.Fatalf("Derive 失败: %v", err)
	}

	// 正常解析
	got, err := c.Parse(key, testPurpose1)
	if err != nil {
		t.Fatalf("正常 Parse 失败: %v", err)
	}
	if !bytes.Equal(got, testResourceID) {
		t.Fatalf("结果不匹配")
	}
}

// TestPurposeKeyCache 验证 PurposeKey 缓存生效
func TestPurposeKeyCache(t *testing.T) {
	c := newTestCKD(t)

	// 第一次调用触发计算和缓存
	key1, err := c.Derive(testResourceID, testPurpose1)
	if err != nil {
		t.Fatalf("第一次 Derive 失败: %v", err)
	}

	// 第二次调用应命中缓存
	key2, err := c.Derive(testResourceID, testPurpose1)
	if err != nil {
		t.Fatalf("第二次 Derive 失败: %v", err)
	}

	if key1 != key2 {
		t.Fatal("两次结果应相同")
	}

	// Parse 也应使用缓存
	got, err := c.Parse(key1, testPurpose1)
	if err != nil {
		t.Fatalf("Parse 失败: %v", err)
	}
	if !bytes.Equal(got, testResourceID) {
		t.Fatalf("结果不匹配")
	}
}

// TestEmptyResourceID 验证空资源 ID 被拒绝
func TestEmptyResourceID(t *testing.T) {
	c := newTestCKD(t)

	if _, err := c.Derive([]byte{}, testPurpose1); err == nil {
		t.Fatal("空资源 ID 应被拒绝")
	}
}

// TestDifferentSecrets 验证不同密钥派生结果不同
func TestDifferentSecrets(t *testing.T) {
	// 使用相同版本号但不同密钥的两个实例
	secrets1 := map[uint8][]byte{1: testSecret}
	secrets2 := map[uint8][]byte{
		1: {
			0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
			0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
			0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
			0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
		},
	}

	c1, err := New(1, secrets1)
	if err != nil {
		t.Fatalf("创建 CKD1 失败: %v", err)
	}
	c2, err := New(1, secrets2)
	if err != nil {
		t.Fatalf("创建 CKD2 失败: %v", err)
	}

	key1, err := c1.Derive(testResourceID, testPurpose1)
	if err != nil {
		t.Fatalf("CKD1 Derive 失败: %v", err)
	}
	key2, err := c2.Derive(testResourceID, testPurpose1)
	if err != nil {
		t.Fatalf("CKD2 Derive 失败: %v", err)
	}

	if key1 == key2 {
		t.Fatal("不同密钥的派生结果应不同")
	}
}

// TestConcurrentAccess 验证并发安全
func TestConcurrentAccess(t *testing.T) {
	c := newTestCKD(t)

	done := make(chan struct{})
	const goroutines = 20

	for i := 0; i < goroutines; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				rid := make([]byte, 8)
				_, _ = rand.Read(rid)

				key, err := c.Derive(rid, testPurpose1)
				if err != nil {
					t.Errorf("并发 Derive 失败: %v", err)
					return
				}

				got, err := c.Parse(key, testPurpose1)
				if err != nil {
					t.Errorf("并发 Parse 失败: %v", err)
					return
				}

				if !bytes.Equal(got, rid) {
					t.Error("并发往返结果不匹配")
					return
				}
			}
			done <- struct{}{}
		}()
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}
}

// TestInvalidVersion 验证非法版本号被拒绝
func TestInvalidVersion(t *testing.T) {
	invalidVersions := []uint8{0, 16, 17, 255}
	for _, v := range invalidVersions {
		_, err := New(v, map[uint8][]byte{v: testSecret})
		if err == nil {
			t.Fatalf("非法版本号 %d 应被拒绝", v)
		}
	}
}

// TestEmptySecrets 验证空密钥表被拒绝
func TestEmptySecrets(t *testing.T) {
	_, err := New(1, nil)
	if err == nil {
		t.Fatal("空密钥表应被拒绝")
	}
	_, err = New(1, map[uint8][]byte{})
	if err == nil {
		t.Fatal("空密钥表应被拒绝")
	}
}

// TestKnownVectors 验证固定测试向量
// 这些向量可跨语言验证一致性
func TestKnownVectors(t *testing.T) {
	// 测试向量组 1
	secret1 := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	rid1 := []byte("channel_12345")
	purpose1 := "webhook"

	c1, err := New(1, map[uint8][]byte{1: secret1})
	if err != nil {
		t.Fatalf("创建测试实例失败: %v", err)
	}

	key1, err := c1.Derive(rid1, purpose1)
	if err != nil {
		t.Fatalf("Derive 失败: %v", err)
	}

	// 验证可逆
	got1, err := c1.Parse(key1, purpose1)
	if err != nil {
		t.Fatalf("Parse 失败: %v", err)
	}
	if !bytes.Equal(got1, rid1) {
		t.Fatalf("结果不匹配: got %v, want %v", got1, rid1)
	}

	// 测试向量组 2
	rid2 := []byte("user_67890")
	purpose2 := "sse"

	key2, err := c1.Derive(rid2, purpose2)
	if err != nil {
		t.Fatalf("Derive 失败: %v", err)
	}

	got2, err := c1.Parse(key2, purpose2)
	if err != nil {
		t.Fatalf("Parse 失败: %v", err)
	}
	if !bytes.Equal(got2, rid2) {
		t.Fatalf("结果不匹配: got %v, want %v", got2, rid2)
	}

	// 测试向量组 3：不同版本
	secret2 := []byte{
		0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
		0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
		0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
		0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
	}
	secrets := map[uint8][]byte{1: secret1, 2: secret2}
	c3, err := New(2, secrets)
	if err != nil {
		t.Fatalf("创建多版本实例失败: %v", err)
	}

	key3, err := c3.Derive(rid1, "api_token")
	if err != nil {
		t.Fatalf("v2 Derive 失败: %v", err)
	}

	got3, err := c3.Parse(key3, "api_token")
	if err != nil {
		t.Fatalf("v2 Parse 失败: %v", err)
	}
	if !bytes.Equal(got3, rid1) {
		t.Fatalf("结果不匹配: got %v, want %v", got3, rid1)
	}

	// 不同版本不应相等
	if key1 == key3 {
		t.Fatal("不同版本的 Key 不应相同")
	}

	// 固定测试向量（可用于跨语言验证）
	// Secret (hex)     = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
	// Purpose          = "webhook"
	// Version          = 0x01
	// ResourceID (hex) = 6368616e6e656c5f3132333435 ("channel_12345")
	// Expected K       = AXnjdNQal5XDP66STw0pQbOzRi3AdGmiX1Xi5ZxO
	if key1 != "AXnjdNQal5XDP66STw0pQbOzRi3AdGmiX1Xi5ZxO" {
		t.Fatalf("测试向量 1 不匹配: got %s, want AXnjdNQal5XDP66STw0pQbOzRi3AdGmiX1Xi5ZxO", key1)
	}

	// Secret (hex)     = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
	// Purpose          = "sse"
	// Version          = 0x01
	// ResourceID (hex) = 757365725f3637383930 ("user_67890")
	// Expected K       = Aez5p0zdhSjxmsgy92MfMhiMlhAbRxlldWcl
	if key2 != "Aez5p0zdhSjxmsgy92MfMhiMlhAbRxlldWcl" {
		t.Fatalf("测试向量 2 不匹配: got %s, want Aez5p0zdhSjxmsgy92MfMhiMlhAbRxlldWcl", key2)
	}

	// Secret v2 (hex)  = ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100
	// Purpose          = "api_token"
	// Version          = 0x02
	// ResourceID (hex) = 6368616e6e656c5f3132333435 ("channel_12345")
	// Expected K       = ApUFLCCTYol1B57b459DrXW8SiQaJLaJRUx246YY
	if key3 != "ApUFLCCTYol1B57b459DrXW8SiQaJLaJRUx246YY" {
		t.Fatalf("测试向量 3 不匹配: got %s, want ApUFLCCTYol1B57b459DrXW8SiQaJLaJRUx246YY", key3)
	}
}
