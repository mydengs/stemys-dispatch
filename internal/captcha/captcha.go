// Package captcha 提供「向右滑动到底」的人机验证（配合深色安全验证弹窗 UI）。
//
// 流程：前端拉起挑战拿一次性 id → 用户把黄色滑块拖到最右 → 前端把进度比例 +
// id 提交 → 服务端校验「比例接近满格 + 距挑战创建已过最小时间（过滤瞬时脚本）+
// 未过期 + 一次性」→ 通过后签发 HMAC 签名通行 cookie（有效期固定）。
package captcha

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	chalTTL       = 3 * time.Minute
	minSolveTime  = 400 * time.Millisecond // 快于此视为脚本
	passRatio     = 0.97                   // 拖到 97% 以上视为“滑到底”
	maxAttempts   = 8
	minTrajPoints = 8   // 轨迹最少采样点数
	minTrajSpanMs = 450 // 轨迹最少跨越时长(ms)
)

type challenge struct {
	createdAt time.Time
	expires   time.Time
	attempts  int
}

// trajOK 校验拖动轨迹质量：真实拖动=多点采样+跨时长+逐段位移有变化(有加减速/微抖动)；
// 脚本模拟常见形态=两点瞬移或匀速无噪声，会被拦下。
// traj 格式："elapsedMs:px,elapsedMs:px,..."（前端从 pointerdown 起计时）。
func trajOK(traj string) bool {
	pairs := strings.Split(traj, ",")
	if len(pairs) < minTrajPoints || len(pairs) > 300 {
		return false
	}
	type pt struct{ t, x float64 }
	pts := make([]pt, 0, len(pairs))
	for _, p := range pairs {
		f := strings.SplitN(p, ":", 2)
		if len(f) != 2 {
			return false
		}
		t, err1 := strconv.ParseFloat(strings.TrimSpace(f[0]), 64)
		x, err2 := strconv.ParseFloat(strings.TrimSpace(f[1]), 64)
		if err1 != nil || err2 != nil {
			return false
		}
		pts = append(pts, pt{t, x})
	}
	if pts[len(pts)-1].t-pts[0].t < minTrajSpanMs {
		return false
	}
	// 时间必须递增；位移大体向前（允许 ≤2 次小幅回退，模拟手抖）
	drops := 0
	prevT, prevX := pts[0].t, pts[0].x
	dxs := make(map[float64]int)
	for _, p := range pts[1:] {
		if p.t <= prevT {
			return false
		}
		dx := p.x - prevX
		if dx < -8 {
			drops++
			if drops > 2 {
				return false
			}
		}
		dxs[math.Round(dx)]++
		prevT, prevX = p.t, p.x
	}
	// 逐段位移种类要够多：纯匀速脚本(所有 dx 相同)种类=1
	if len(dxs) < 4 {
		return false
	}
	return true
}

type Manager struct {
	mu     sync.Mutex
	m      map[string]*challenge
	secret string
}

func NewManager(secret string) *Manager {
	mg := &Manager{m: map[string]*challenge{}, secret: secret}
	go mg.gc()
	return mg
}

func (mg *Manager) gc() {
	for {
		time.Sleep(time.Minute)
		now := time.Now()
		mg.mu.Lock()
		for k, c := range mg.m {
			if now.After(c.expires) {
				delete(mg.m, k)
			}
		}
		mg.mu.Unlock()
	}
}

func randID() string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// NewChallenge 生成一个一次性挑战 id。
func (mg *Manager) NewChallenge() string {
	id := randID()
	now := time.Now()
	mg.mu.Lock()
	mg.m[id] = &challenge{createdAt: now, expires: now.Add(chalTTL), attempts: maxAttempts}
	mg.mu.Unlock()
	return id
}

// Verify 校验拖动进度比例（0~1）与轨迹质量。
func (mg *Manager) Verify(id string, ratio float64, traj string) bool {
	mg.mu.Lock()
	defer mg.mu.Unlock()
	c, ok := mg.m[id]
	if !ok || time.Now().After(c.expires) {
		return false
	}
	c.attempts--
	if ratio >= passRatio && time.Since(c.createdAt) >= minSolveTime && trajOK(traj) {
		delete(mg.m, id)
		return true
	}
	if c.attempts <= 0 {
		delete(mg.m, id)
	}
	return false
}

// ---- 通行 cookie ----

func mac(secret, payload string) []byte {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(payload))
	return h.Sum(nil)
}

// PassToken 生成有效期到 exp 的通行令牌。
func PassToken(secret string, exp time.Time) string {
	p := strconv.FormatInt(exp.Unix(), 10)
	return p + "." + hex.EncodeToString(mac(secret, "hum|"+p))
}

// CheckPass 校验通行令牌。
func CheckPass(secret, tok string) bool {
	parts := strings.SplitN(tok, ".", 2)
	if len(parts) != 2 {
		return false
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	want := hex.EncodeToString(mac(secret, "hum|"+parts[0]))
	return hmac.Equal([]byte(parts[1]), []byte(want))
}

// ---- HTTP 处理器 ----

// HandleChallenge GET → 返回一次性挑战 id。
func (mg *Manager) HandleChallenge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{"id": mg.NewChallenge()})
}

// HandleVerify POST → 校验并签发通行 cookie。
func (mg *Manager) HandleVerify(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	ratio, _ := strconv.ParseFloat(r.FormValue("ratio"), 64)
	ok := mg.Verify(id, ratio, r.FormValue("traj"))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if ok {
		http.SetCookie(w, &http.Cookie{
			Name: "hum", Value: PassToken(mg.secret, time.Now().Add(2*time.Hour)),
			Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 2 * 3600,
		})
	}
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": ok})
}
