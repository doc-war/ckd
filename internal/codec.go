package internal

import (
	"encoding/base64"
	"errors"
)

const (
	headerByteSize = 1   // 版本号占 1 字节
	maxVersion     = 15  // 最大版本号
	authTagSize    = 16  // AES-SIV 认证标签长度
)

// ErrInvalidEncoding 无效的编码格式
var ErrInvalidEncoding = errors.New("无效的编码格式")

// Encode 编码为 base64url(header_byte || data)，不带 padding
// header_byte bit0-3 = version，bit4-7 = reserved（生成时必须为 0）
func Encode(version uint8, data []byte) (string, error) {
	if version < 1 || version > maxVersion {
		return "", errors.New("版本号必须在 [1,15] 范围内")
	}

	header := version & 0x0F // reserved 位填 0
	wire := make([]byte, 0, headerByteSize+len(data))
	wire = append(wire, header)
	wire = append(wire, data...)

	return base64.RawURLEncoding.EncodeToString(wire), nil
}

// Decode 解码 base64url 编码的派生密钥
// 返回 (version, data, error)
func Decode(encoded string) (uint8, []byte, error) {
	wire, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return 0, nil, ErrInvalidEncoding
	}
	if len(wire) < headerByteSize+authTagSize {
		return 0, nil, ErrInvalidEncoding
	}

	header := wire[0]
	version := header & 0x0F
	// reserved 位 (bit4-7) 被忽略，保证向前兼容

	if version < 1 || version > maxVersion {
		return 0, nil, ErrInvalidEncoding
	}

	return version, wire[headerByteSize:], nil
}
