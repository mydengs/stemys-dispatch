// Package sign 生成和校验「带有效期、防篡改、防刷」的分享链接 token。
//
// token 结构: base64url(payload) "." base64url(hmac_sha256(secret, payload))
// payload  结构: "<shareID>.<expUnix>.<nonce>"
//
// 服务端校验签名（防篡改）+ 过期时间（有效期）+ 数据库里的开关/次数上限（防刷）。
package sign

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var (
	ErrMalformed = errors.New("token 格式错误")
	ErrBadSig    = errors.New("token 签名校验失败")
	ErrExpired   = errors.New("token 已过期")
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func mac(secret, payload string) []byte {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(payload))
	return m.Sum(nil)
}

// Sign 为某个 share ID 生成有效期到 expires 的 token。
func Sign(secret string, shareID int64, expires time.Time) string {
	nb := make([]byte, 9)
	_, _ = rand.Read(nb)
	payload := fmt.Sprintf("%d.%d.%s", shareID, expires.Unix(), b64(nb))
	return b64([]byte(payload)) + "." + b64(mac(secret, payload))
}

// Verify 校验 token，返回 shareID 与过期时间。
func Verify(secret, token string) (int64, time.Time, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return 0, time.Time{}, ErrMalformed
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return 0, time.Time{}, ErrMalformed
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, time.Time{}, ErrMalformed
	}
	payload := string(payloadBytes)
	if !hmac.Equal(sig, mac(secret, payload)) {
		return 0, time.Time{}, ErrBadSig
	}
	fields := strings.Split(payload, ".")
	if len(fields) != 3 {
		return 0, time.Time{}, ErrMalformed
	}
	id, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return 0, time.Time{}, ErrMalformed
	}
	exp, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0, time.Time{}, ErrMalformed
	}
	expT := time.Unix(exp, 0)
	if time.Now().After(expT) {
		return id, expT, ErrExpired
	}
	return id, expT, nil
}

// Seal/Unseal 通用「防篡改短令牌」（payload 由调用方自定义，内部用 | 分字段）。
// 与 Sign/Verify 的区别：不经 share 表，适合纯 cookie 状态（如随机前缀回访粘性）。

// Seal 生成 base64url(payload).base64url(hmac) 令牌。
func Seal(secret, payload string) string {
	return b64([]byte(payload)) + "." + b64(mac(secret, payload))
}

// Unseal 校验签名并返回 payload；格式/签名不对返回 ok=false。
func Unseal(secret, tok string) (string, bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 2 {
		return "", false
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	payload := string(payloadBytes)
	if !hmac.Equal(sig, mac(secret, payload)) {
		return "", false
	}
	return payload, true
}
