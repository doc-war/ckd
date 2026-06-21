# CKD — Channel Key Derivation

轻量级、无状态、可逆的资源标识派生协议 Go SDK。

CKD 的核心目标：

- 一个内部资源 ID，可以派生多个用途隔离的外部 Key
- 无数据库映射
- 可逆恢复
- 不同用途之间不可互相推导。

在数学上的具体表现为：

- C → A
- C → B
- A → C
- B → C
- A 无法推导 B
- B 无法推导 A
- 不需要存储 A→C、B→C映射，仅依赖平台密钥即可完成派生和反向解析
- 且无法使用已知的AB来反向破解密钥

## 安装

```bash
go get github.com/doc-war/ckd
```

零外部依赖，仅使用 Go 标准库。

## 快速开始

```go
package main

import (
    "fmt"
    "github.com/doc-war/ckd"
)

func main() {
    // 主密钥：32 字节高熵随机字节串（CSPRNG 生成）
    secret := []byte{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    }

    c, err := ckd.New(ckd.Config{
        CurrentVersion: 1,
        SecretsByVersion: map[uint8][]byte{
            1: secret,
        },
    })
    if err != nil {
        panic(err)
    }

    // 派生：内部 ID → 外部 Key
    channelID := []byte("channel_12345")
    webhookKey, _ := c.Derive(channelID, "webhook")
    sseKey, _ := c.Derive(channelID, "sse")

    fmt.Println(webhookKey) // 例如: AXnjdNQal5XDP66STw0pQbOzRi3AdGmiX1Xi5ZxO

    // 恢复：外部 Key → 内部 ID
    recovered, _ := c.Parse(webhookKey, "webhook")
    fmt.Println(string(recovered)) // channel_12345
}
```

## 核心概念

| 概念 | 说明 |
|---|---|
| **资源 ID (C)** | 内部资源标识，如 channel_id, user_id |
| **用途 (P)** | 用途标识，如 `webhook`, `sse`, `api`，仅允许 `[a-z0-9_-]`，长度 1~64 |
| **派生密钥 (K)** | 外部标识，base64url 编码，含版本号和认证标签 |
| **主密钥 (S)** | 平台主密钥，推荐 256-bit CSPRNG 字节串 |

## 协议流程

```
派生: K = base64url(version_byte || AES-SIV-Encrypt(PurposeKey, C, AAD=P))
恢复: C = AES-SIV-Decrypt(PurposeKey, base64url-decode(K), AAD=P)
密钥: PurposeKey = HKDF(S, salt="", info=P)
```

## API 参考

### New

```go
func New(cfg Config) (CKD, error)
```

| Config 字段 | 类型 | 说明 |
|---|---|---|
| `CurrentVersion` | `uint8` | 当前版本号 [1, 15] |
| `SecretsByVersion` | `map[uint8][]byte` | 各版本密钥，需包含 CurrentVersion |

### CKD 接口

```go
type CKD interface {
    Derive(resourceID []byte, purpose string) (string, error)
    Parse(derivedKey string, purpose string) ([]byte, error)
}
```

### 错误处理

```go
if errors.Is(err, ckd.ErrInvalidPurpose) {
    // 用途标识格式不合法
}
if errors.Is(err, ckd.ErrInvalidDerivedKey) {
    // 派生密钥解析失败（格式错误、认证失败、版本不存在等）
}
```

`Parse` 对认证失败、格式错误、版本不存在等情况返回统一的 `ErrInvalidDerivedKey`，不泄露失败原因。

## 密钥轮换

```go
c, _ := ckd.New(ckd.Config{
    CurrentVersion: 2,
    SecretsByVersion: map[uint8][]byte{
        1: oldSecret,  // 旧密钥，用于解析旧 Key
        2: newSecret,  // 新密钥，用于新派生
    },
})

// 新派生使用 v2
newKey, _ := c.Derive(channelID, "webhook")

// 旧 Key 仍可被解析（v1 密钥保留在表中）
oldID, _ := c.Parse(oldKey, "webhook")
```

## 用途隔离

不同 purpose 派生出的 Key 不可互相推导：

```go
k1, _ := c.Derive(id, "webhook")
k2, _ := c.Derive(id, "sse")

// k1 ≠ k2
// Parse(k1, "sse") → 错误
// Parse(k2, "webhook") → 错误
```

## 算法

| 组件 | 算法 | 标准 |
|---|---|---|
| 密钥派生 | HKDF (SHA-256) | RFC 5869 |
| 确定性 AEAD | AES-256-SIV | RFC 5297 |
| 编码 | base64url (无 padding) | RFC 4648 §5 |

## 测试向量

3 组固定向量用于跨语言验证，见 `internal/core_test.go` `TestKnownVectors`。

| # | Secret | Purpose | Ver | ResourceID | K |
|---|---|---|---|---|---|
| 1 | `0001...1e1f` (32B) | `webhook` | 1 | `channel_12345` | `AXnjdNQal5XDP66STw0pQbOzRi3AdGmiX1Xi5ZxO` |
| 2 | `0001...1e1f` (32B) | `sse` | 1 | `user_67890` | `Aez5p0zdhSjxmsgy92MfMhiMlhAbRxlldWcl` |
| 3 | `ffee...1100` (32B) | `api_token` | 2 | `channel_12345` | `ApUFLCCTYol1B57b459DrXW8SiQaJLaJRUx246YY` |

## 安全特性

- **用途隔离**：不同 purpose 使用独立的密钥空间和认证上下文
- **不可伪造**：AEAD 认证加密防止篡改
- **密钥保护**：给定 K 无法推断主密钥 S
- **常数时间**：认证失败统一返回，不泄露失败原因
- **确定性**：相同输入始终产出相同输出

## 已知限制

- 不支持单点撤销（需要上层维护黑名单）
- 不隐藏资源 ID 长度（AES-SIV 为长度保持型加密）
- 等价性可观察（相同 C 产生的 K 可被关联）
- 协议层只对最终传入的 `C` 负责，版本派生、撤销、熵扩展等需求均下放给上层处理

## 许可

MIT
