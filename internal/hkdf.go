package internal

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

// hkdfExpand 实现 HKDF-Expand（RFC 5869 第 2.3 节）
// 从 PRK 派生出指定长度的密钥材料
// prk: 伪随机密钥（HKDF-Extract 的输出）
// info: 可选上下文信息
// length: 目标密钥长度
func hkdfExpand(prk, info []byte, length int) ([]byte, error) {
	if length > 255*sha256.Size {
		return nil, errors.New("hkdf: 请求长度超出上限")
	}

	result := make([]byte, 0, length)
	t := make([]byte, 0, sha256.Size)

	counter := byte(1)
	for len(result) < length {
		mac := hmac.New(sha256.New, prk)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{counter})
		t = mac.Sum(nil)
		result = append(result, t...)
		counter++
	}

	return result[:length], nil
}

// derivePurposeKey 使用 HKDF 派生得到 PurposeKey
// 算法：PurposeKey = HKDF(Secret, salt="", info=Purpose)
// 实现：HKDF-Extract + HKDF-Expand（RFC 5869）
func derivePurposeKey(secret []byte, purpose string) []byte {
	// HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
	// salt = 空字符串（32 字节全零）
	salt := make([]byte, sha256.Size)
	mac := hmac.New(sha256.New, salt)
	mac.Write(secret)
	prk := mac.Sum(nil)

	// HKDF-Expand: OKM = HKDF-Expand(PRK, info, L)
	key, err := hkdfExpand(prk, []byte(purpose), purposeKeyLen)
	if err != nil {
		panic(err) // purposeKeyLen = 64，远小于 255*32，不会失败
	}
	return key
}
