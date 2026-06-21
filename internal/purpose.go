package internal

import "errors"

// ErrInvalidPurpose 无效的用途标识
var ErrInvalidPurpose = errors.New("无效的用途标识")

// ValidatePurpose 校验 purpose 格式
// 规则：仅允许 [a-z0-9_-]，长度 1~64 字节，不得有首尾空白
func ValidatePurpose(purpose string) error {
	if len(purpose) == 0 || len(purpose) > 64 {
		return ErrInvalidPurpose
	}
	for i := 0; i < len(purpose); i++ {
		b := purpose[i]
		if !((b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_' || b == '-') {
			return ErrInvalidPurpose
		}
	}
	return nil
}
