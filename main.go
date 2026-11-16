package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"stemys/dispatch/internal/admin"
	"stemys/dispatch/internal/captcha"
	"stemys/dispatch/internal/dispatch"
	"stemys/dispatch/internal/sign"
	"stemys/dispatch/internal/store"
)

type Config struct {
	Listen         string `json:"listen"`
	DBPath         string `json:"dbpath"`
	Secret         string `json:"secret"`
	FallbackURL    string `json:"fallback_url"`    // 无匹配 offer 时的兜底跳转
	DisableCaptcha bool   `json:"disable_captcha"` // true = 关闭入口滑块人机验证
}

func loadConfig(path string) (*Config, error) {
	c := &Config{Listen: "127.0.0.1:8801", DBPath: "data.db"}
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, c); err != nil {
			return nil, err
		}
	}
	if c.Secret == "" {
		nb := make([]byte, 32)
		_, _ = rand.Read(nb)
		c.Secret = hex.EncodeToString(nb)
		log.Printf("[config] 未配置 secret，已生成临时密钥（重启后分享链接将失效，请写入配置文件固定下来）")
	}
	return c, nil
}

func main() {
	cfgPath := "config.json"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		log.Fatalf("读取配置失败: %v", err)
	}
	db, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	// 地域兜底必须重启后也生效：启动时从库读回，否则 CN 类定向会在重启后静默变砖（实测踩坑）
	if cc := db.GetConfig("default_country", ""); cc != "" {
		dispatch.SetDefaultCountry(cc)
		log.Printf("[config] 地域兜底 default_country=%s（无国家注头时按此判定）", cc)
	}

	ad := admin.New(db, cfg.Secret)
	capMgr := captcha.NewManager(cfg.Secret)

	mux := http.NewServeMux()
	// 后台
	mux.Handle("/admin/", ad.Handler())
	// 健康检查
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	// 入口卫生端点：robots 全站禁收录；favicon 直供（不进分发逻辑、不记点击）
	mux.HandleFunc("/robots.txt", handleEntryRobots)
	mux.HandleFunc("/favicon.ico", handleFavicon)
	// 人机验证（滑块）挑战 + 校验
	mux.HandleFunc("/captcha/challenge", capMgr.HandleChallenge)
	mux.HandleFunc("/captcha/verify", capMgr.HandleVerify)
	// 分享链接
	mux.HandleFunc("/s/", func(w http.ResponseWriter, r *http.Request) {
		handleShare(w, r, db, cfg)
	})
	// 其它所有路径 → 分发
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleDispatch(w, r, db, cfg)
	})

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           logging(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("分发系统启动: http://%s  (后台 /admin)", cfg.Listen)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 入口/后台一律声明 noindex，搜索引擎与厂商爬虫不会收录验证页/伪装页
		if !strings.HasPrefix(r.URL.Path, "/admin/static") {
			w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		}
		t := time.Now()
		next.ServeHTTP(w, r)
		if !strings.HasPrefix(r.URL.Path, "/admin/static") && !strings.HasPrefix(r.URL.Path, "/admin/health") {
			log.Printf("%s %s%s %s %s", r.Method, r.Host, r.URL.Path, r.URL.RawQuery, time.Since(t))
		}
	})
}

func humCookie(r *http.Request) string {
	if c, err := r.Cookie("hum"); err == nil {
		return c.Value
	}
	return ""
}

// carrierGate 网络类型分类：先查机房黑名单（deny），再查运营商白名单（carrier），都不中 = other。
// 模式存 site_config.carrier_gate：off|observe|strict；白名单为空时等同 off（不误伤）。
// 说明：carrier 只表示「出口 IP 属于运营商公告前缀池」——同池内 4G/5G 与家宽无法用 IP 精确区分；
// 挂在运营商线路上的机房/IDC 也可能落进白名单，故黑名单判定优先于白名单。
func carrierGate(db *store.DB, r *http.Request) (mode, cls string) {
	mode = db.GetConfig("carrier_gate", "observe")
	if mode == "off" {
		return mode, ""
	}
	allowNets := dispatch.ParseCIDRs(splitLines(db.GetConfig("carrier_cidrs", "")))
	if len(allowNets) == 0 {
		return "off", ""
	}
	denyNets := dispatch.ParseCIDRs(splitLines(db.GetConfig("blocker_cidrs", "")))
	ip := dispatch.ClientIP(r)
	switch {
	case dispatch.IsIPBlocked(ip, denyNets):
		cls = "deny"
	case dispatch.IsIPBlocked(ip, allowNets):
		cls = "carrier"
	default:
		cls = "other"
	}
	return mode, cls
}

// lpCookieName 回访粘性 cookie：记「本次绑定的随机前缀 + 所属 offer + 到期时间」（HMAC 签名防篡改）。
const lpCookieName = "lp"

// subLabelRe 合法随机前缀：小写字母开头 + 小写字母数字，总长 8~11（与 dispatch.RandomSubLabel 一致）。
var subLabelRe = regexp.MustCompile(`^[a-z][a-z0-9]{7,10}$`)

// landingFor 计算本次访问的落地地址：
//   - 非 random 模式：照常返回固定落地。
//   - random + 无粘性（sticky_ttl=0）：每次现场生成新前缀；若浏览器残留旧 lp cookie 顺手清掉。
//   - random + 粘性（sticky_ttl>0）：lp cookie 有效（签名合法、offer 匹配、前缀合法、未过期）→ 沿用其前缀，
//     并滑动续期重发 cookie；无效/超期 → 生成全新前缀并下发新 cookie。
//
// 返回 (落地地址, 需要附加的 cookie)，cookie 为 nil 时无需 Set-Cookie。
func landingFor(offer *store.Offer, r *http.Request, secret string) (string, *http.Cookie) {
	if offer == nil {
		return "", nil
	}
	if !offer.IsRandomSub() {
		return offer.LandingURL(), nil
	}
	if offer.StickyTTL <= 0 {
		ck := (*http.Cookie)(nil)
		if _, err := r.Cookie(lpCookieName); err == nil {
			ck = &http.Cookie{Name: lpCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode}
		}
		return offer.LandingURLFor(dispatch.RandomSubLabel()), ck
	}
	sub := ""
	if c, err := r.Cookie(lpCookieName); err == nil {
		if pl, ok := sign.Unseal(secret, c.Value); ok {
			fs := strings.Split(pl, "|") // 格式: sub|offerID|expUnix
			if len(fs) == 3 && fs[1] == strconv.FormatInt(offer.ID, 10) && subLabelRe.MatchString(fs[0]) {
				exp, _ := strconv.ParseInt(fs[2], 10, 64)
				if time.Now().Unix() < exp {
					sub = fs[0]
				}
			}
		}
	}
	if sub == "" {
		sub = dispatch.RandomSubLabel()
	}
	exp := time.Now().Add(time.Duration(offer.StickyTTL) * time.Second)
	ck := &http.Cookie{
		Name:     lpCookieName,
		Value:    sign.Seal(secret, fmt.Sprintf("%s|%d|%d", sub, offer.ID, exp.Unix())),
		Path:     "/",
		MaxAge:   int(offer.StickyTTL),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	return offer.LandingURLFor(sub), ck
}

// handleDispatch 是核心：识别域 → campaign → 分流 → 记日志 → 302。
func handleDispatch(w http.ResponseWriter, r *http.Request, db *store.DB, cfg *Config) {
	v := dispatch.Parse(r)
	mode, ipcls := carrierGate(db, r)

	// 防采集伪装：爬虫/探测型请求直接给中性公告页，
	// 不出验证页、不出 302，厂商采集不到分发行为与落地域名。
	if enabled, crawler := decoyEnabledAndCrawler(db, r); enabled && crawler {
		logDecoyHit(db, v, r, ipcls)
		serveDecoy(w, db)
		return
	}

	// 网络类型闸门（strict 模式）：运营商白名单外的访客（云/机房/政企专线/教育网/VPN 出口）
	// 一律看伪装页——新域名投放时只放行真实家宽/蜂窝流量，白名单外连验证页都不给。
	if mode == "strict" && ipcls == "other" {
		c := dispatch.BuildClick(v, nil, "", r, 0)
		c.Landing = "gate_block"
		c.IPClass = ipcls
		_ = db.InsertClick(&c)
		serveDecoy(w, db)
		return
	}

	// 人机验证闸门：未通过滑块验证先出验证页（通过后签发 2h 通行 cookie）
	if !cfg.DisableCaptcha && !captcha.CheckPass(cfg.Secret, humCookie(r)) {
		serveCaptchaGate(w)
		return
	}

	dom, err := db.ResolveDomain(v.Host)
	if err != nil {
		http.Error(w, "db error", 500)
		return
	}
	var campaign string
	if dom != nil && dom.Enabled {
		campaign = dom.Campaign
	} else {
		// 未登记或已停用的域，直接用全局 campaign（空 = 匹配所有空 campaign 的 offer）
		campaign = ""
	}

	offers, err := db.ActiveOffers()
	if err != nil {
		http.Error(w, "db error", 500)
		return
	}
	offer := dispatch.Select(offers, v, campaign)

	click := dispatch.BuildClick(v, offer, campaign, r, 0)
	click.IPClass = ipcls

	// 计算实际落地地址：random 模式现场生成新前缀；设了「回访有效期」则有效期内沿用同一前缀并续期（见 landingFor）
	landing, lpck := landingFor(offer, r, cfg.Secret)
	click.Landing = landing
	if lpck != nil {
		http.SetCookie(w, lpck)
	}
	_ = db.InsertClick(&click)

	if offer == nil {
		if cfg.FallbackURL != "" {
			http.Redirect(w, r, cfg.FallbackURL, http.StatusFound)
			return
		}
		http.Error(w, "暂无可用的落地页（no offer matched）", http.StatusNotFound)
		return
	}
	http.Redirect(w, r, landing, http.StatusFound)
}

// handleShare 校验分享链接签名/有效期/次数，记日志并跳转。
func handleShare(w http.ResponseWriter, r *http.Request, db *store.DB, cfg *Config) {
	token := strings.TrimPrefix(r.URL.Path, "/s/")
	token = strings.TrimSuffix(token, "/")
	if token == "" {
		http.NotFound(w, r)
		return
	}
	// 厂商安全爬虫探测分享链接：直接给伪装页，不给 302，落地域名不外泄
	mode, ipcls := carrierGate(db, r)
	if enabled, crawler := decoyEnabledAndCrawler(db, r); enabled && crawler {
		logDecoyHit(db, dispatch.Parse(r), r, ipcls)
		serveDecoy(w, db)
		return
	}
	// 网络类型闸门（strict）：白名单外访客探分享链接同样只见伪装页
	if mode == "strict" && ipcls == "other" {
		c := dispatch.BuildClick(dispatch.Parse(r), nil, "", r, 0)
		c.Landing = "gate_block"
		c.IPClass = ipcls
		_ = db.InsertClick(&c)
		serveDecoy(w, db)
		return
	}
	// 与入口同一闸门：不执行 JS 的采集器先出验证页，吃不到 302
	if !cfg.DisableCaptcha && !captcha.CheckPass(cfg.Secret, humCookie(r)) {
		serveCaptchaGate(w)
		return
	}
	_, _, err := sign.Verify(cfg.Secret, token)
	if err != nil {
		expiredPage(w, http.StatusForbidden, err.Error())
		return
	}
	sl, err := db.GetShareByToken(token)
	if err != nil || sl == nil {
		expiredPage(w, http.StatusNotFound, "链接不存在")
		return
	}
	if !sl.Enabled {
		expiredPage(w, http.StatusForbidden, "链接已被停用")
		return
	}
	if time.Now().After(sl.ExpiresAt) {
		expiredPage(w, http.StatusForbidden, "链接已过期")
		return
	}
	if sl.MaxClicks > 0 && sl.Clicks >= sl.MaxClicks {
		expiredPage(w, http.StatusForbidden, "链接访问次数已达上限")
		return
	}
	// 记一次点击 + 计数
	v := dispatch.Parse(r)
	click := dispatch.BuildClick(v, nil, "share", r, sl.ID)
	click.OfferName = sl.Note
	click.IPClass = ipcls
	_ = db.InsertClick(&click)
	_ = db.IncShareClicks(sl.ID)

	http.Redirect(w, r, sl.TargetURL, http.StatusFound)
}

// serveCaptchaGate 输出滑块验证页：不执行 JS 的采集器只能看到本页，
// 页内只有相对路径，不含任何落地域名信息。
func serveCaptchaGate(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(captcha.PageHTML()))
}

// handleEntryRobots 入口域 robots.txt：全站 Disallow，礼貌劝退搜索引擎收录，
// 也让爬虫的 robots 探测直接命中 200 而不进分发逻辑产生噪音点击记录。
func handleEntryRobots(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write([]byte("User-agent: *\nDisallow: /\n"))
}

// faviconIco：16x16 全透明 .ico。浏览器/webview 打开入口时会自动请求 favicon，
// 若走分发逻辑会被多计一次点击、且验证通过后会形成 302 链供厂商观察，
// 故直供固定小图标：不记点击、不跳转。
const faviconB64 = "AAABAAEAEBAAAAEAIABIBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAIAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

var faviconIco []byte

func init() {
	if b, err := base64.StdEncoding.DecodeString(faviconB64); err == nil {
		faviconIco = b
	}
}

func handleFavicon(w http.ResponseWriter, r *http.Request) {
	if len(faviconIco) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "image/x-icon")
	w.Header().Set("Cache-Control", "public, max-age=604800")
	_, _ = w.Write(faviconIco)
}
