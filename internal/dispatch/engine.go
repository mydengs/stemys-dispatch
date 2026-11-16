// Package dispatch 负责把一次访问请求解析成「设备/地域/渠道」，并按规则选择落地页。
package dispatch

import (
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync/atomic"

	"stemys/dispatch/internal/store"
)

// Visitor 解析后的访客上下文。
type Visitor struct {
	Host      string
	Device    string // mobile|tablet|desktop
	Country   string // ISO 国家码，未知为 ZZ
	Channel   string // wechat|qq|douyin|... 或 utm_source 原值
	UTMSource string
	UTMMedium string
	Referer   string
	UA        string
	Bot       bool
}

// ---- 设备识别 ----
func detectDevice(ua string) string {
	u := strings.ToLower(ua)
	switch {
	case strings.Contains(u, "ipad"), strings.Contains(u, "tablet"), strings.Contains(u, "kindle"),
		(strings.Contains(u, "android") && !strings.Contains(u, "mobile")):
		return "tablet"
	case strings.Contains(u, "mobile"), strings.Contains(u, "iphone"), strings.Contains(u, "android"),
		strings.Contains(u, "windows phone"), strings.Contains(u, "micromessenger"):
		return "mobile"
	default:
		return "desktop"
	}
}

// ---- 机器人识别（反作弊：命中则标记 bot，不计入有效点击） ----
var botUASubstrings = []string{
	"bot", "spider", "crawler", "slurp", "curl", "wget", "python-requests",
	"headlesschrome", "phantomjs", "apache-httpclient", "go-http-client",
	"bytespider", "baiduspider", "yandex", "bingpreview", "facebookexternalhit",
	"semrush", "ahrefs", "mj12", "scan",
}

// vendorProbeSubstrings 专治「不含 bot/spider 字样」的厂商浏览器安全探针与链接展开器：
// QQ/微信安全中心、微信分享链接卡片预览、Google 兜底爬虫、WhatsApp 链接展开、ChatGPT 抓取器。
// 只用于 IsCrawler 伪装闸门（配合厂商云侧 IP 段兜底），不影响普通点击的 bot 统计口径。
var vendorProbeSubstrings = []string{
	"tencentsecurityticker",                          // QQ浏览器/腾讯安全 URL 检测
	"qqexternal",                                     // QQ 外部链接通知抓取
	"wechatsharelinknewsmartpreview",                 // 微信分享链接智能预览（生成聊天卡片）
	"wechaturlsecurityticker",                        // 微信链接安全检测
	"googleother",                                    // Google 兜底爬虫（App Indexing / Feed）
	"chatgpt-agent", "chatgpt-user", "oai-searchbot", // OpenAI 抓取器
	"whatsapp/",       // WhatsApp 链接展开
	"skypeuripreview", // Skype 链接预览
	"pinterestbot",
	"linkpreview", "urlscan", "sitepupil", "changedetection",
}

func detectBot(ua, referer string) bool {
	_ = referer
	if strings.TrimSpace(ua) == "" {
		return true
	}
	u := strings.ToLower(ua)
	for _, s := range botUASubstrings {
		if strings.Contains(u, s) {
			return true
		}
	}
	return false
}

// ---- 地域识别 ----
// 优先读 CDN/nginx 注入的国家头（Cloudflare 用 CF-IPCountry，nginx geoip 用 X-Country-Code）。
// 无头时用 DefaultCountry 兜底（后台 site_config.default_country 可设，如 CN）；
// 未设置保持 ZZ（兼容 Cloudflare/geoip 部署，行为不变）。
var defaultCountry atomic.Value // string

func SetDefaultCountry(cc string) { defaultCountry.Store(strings.ToUpper(strings.TrimSpace(cc))) }

func GetDefaultCountry() string {
	if v, ok := defaultCountry.Load().(string); ok {
		return v
	}
	return ""
}

func detectCountry(r *http.Request) string {
	for _, h := range []string{"CF-IPCountry", "X-Country-Code", "X-Geo-Country", "X-Country"} {
		if v := strings.TrimSpace(r.Header.Get(h)); v != "" {
			return strings.ToUpper(v)
		}
	}
	if cc := GetDefaultCountry(); cc != "" {
		return cc
	}
	return "ZZ"
}

// ---- 渠道识别 ----
// 1) 优先 utm_source（可自定义）；2) 否则按 referer / UA 推断微信、QQ、抖音。
func detectChannel(r *http.Request, ua string) string {
	q := r.URL.Query()
	if s := strings.ToLower(strings.TrimSpace(q.Get("utm_source"))); s != "" {
		return s
	}
	// 厂商 webview 自带的包名标识头（X5 内核改写 UA 时仍可按来源归因）
	switch r.Header.Get("X-Requested-With") {
	case "com.tencent.mm":
		return "wechat"
	case "com.tencent.mobileqq":
		return "qq"
	case "com.ss.android.ugc.aweme", "com.ss.android.ugc.aweme.lite":
		return "douyin"
	}
	u := strings.ToLower(ua)
	ref := strings.ToLower(r.Referer())
	switch {
	case strings.Contains(u, "micromessenger"), strings.Contains(ref, "weixin.qq.com"):
		return "wechat"
	case strings.Contains(u, "qq/"), strings.Contains(u, "qqbrowser"), strings.Contains(ref, "qq.com"):
		return "qq"
	case strings.Contains(ref, "douyin"), strings.Contains(ref, "iesdouyin"), strings.Contains(u, "aweme"),
		strings.Contains(ref, "bytedance"), strings.Contains(u, "bytedance"):
		return "douyin"
	}
	return "direct"
}

func hashIP(ip string) string {
	sum := sha256.Sum256([]byte(ip))
	return hex.EncodeToString(sum[:])[:16]
}

func clientIP(r *http.Request) string {
	if v := r.Header.Get("CF-Connecting-IP"); v != "" {
		return v
	}
	if v := r.Header.Get("X-Real-IP"); v != "" {
		return v
	}
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		return strings.TrimSpace(strings.Split(v, ",")[0])
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	return host
}

// Parse 把请求解析成 Visitor。
func Parse(r *http.Request) Visitor {
	ua := r.UserAgent()
	q := r.URL.Query()
	host := r.Host
	if h := r.Header.Get("X-Forwarded-Host"); h != "" {
		host = h
	}
	host = strings.ToLower(host)
	// 直连非 80/443 端口时浏览器会在 Host 里带端口（如 zz.a.b.com:8801），登记域名不带端口，这里剥掉
	if i := strings.LastIndex(host, ":"); i >= 0 && !strings.Contains(host[i:], "]") {
		host = host[:i]
	}
	return Visitor{
		Host:      host,
		Device:    detectDevice(ua),
		Country:   detectCountry(r),
		Channel:   detectChannel(r, ua),
		UTMSource: q.Get("utm_source"),
		UTMMedium: q.Get("utm_medium"),
		Referer:   r.Referer(),
		UA:        ua,
		Bot:       detectBot(ua, r.Referer()),
	}
}

// ClientIP 返回请求链路中的客户端 IP（对外包装：CF 头 → X-Real-IP → XFF 首段 → RemoteAddr）。
func ClientIP(r *http.Request) string { return clientIP(r) }

// ParseCIDRs 逐行解析 CIDR 列表（非法行静默忽略；裸 IP 按 /32 或 /128 处理）。
func ParseCIDRs(lines []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if !strings.Contains(l, "/") {
			if ip := net.ParseIP(l); ip != nil {
				if ip.To4() != nil {
					l += "/32"
				} else {
					l += "/128"
				}
			}
		}
		if _, n, err := net.ParseCIDR(l); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}

// IsIPBlocked 客户端 IP 是否命中 CIDR 黑名单（解析失败视为不命中）。
func IsIPBlocked(ip string, nets []*net.IPNet) bool {
	if len(nets) == 0 {
		return false
	}
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// IsCrawler 判定「采集/探测型」请求：通用爬虫 + 厂商安全探针 UA + 后台补充 UA 关键字 +
// 预取/预览类请求头 + HEAD/OPTIONS 探测 + 厂商云侧 IP 段。
// 浏览器厂商（QQ/微信/vivo/三星/苹果等）的安全检测与链接预取常不带 bot 字样，
// 靠 Purpose/Sec-Purpose/X-Purpose 的 prefetch|preview|instant|display 等值、
// 以及 HEAD 试探、机房 IP 兜底来识别；IP 段命中时无条件判定，UA 伪装失效。
func IsCrawler(r *http.Request, extra []string, cidrs []*net.IPNet) bool {
	if IsIPBlocked(clientIP(r), cidrs) {
		return true
	}
	// 链接检测器/安全中心偏爱 HEAD、OPTIONS 试探（真实浏览器导航一律 GET）
	if r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return true
	}
	ua := r.UserAgent()
	if detectBot(ua, r.Referer()) {
		return true
	}
	u := strings.ToLower(ua)
	for _, t := range vendorProbeSubstrings {
		if strings.Contains(u, t) {
			return true
		}
	}
	for _, t := range extra {
		t = strings.ToLower(strings.TrimSpace(t))
		if t != "" && strings.Contains(u, t) {
			return true
		}
	}
	// 浏览器预取/即时加载/链接预览类请求头（厂商自带浏览器的「秒开」预取也走这些头）
	for _, h := range []string{"Purpose", "Sec-Purpose", "X-Purpose"} {
		v := strings.ToLower(r.Header.Get(h))
		for _, want := range []string{"prefetch", "unload", "preview", "instant", "display", "unsafe-url"} {
			if strings.Contains(v, want) {
				return true
			}
		}
	}
	return false
}

// RandomSubLabel 生成一个随机子域前缀（字母开头 + 字母数字，8~11 位），
// 用于「每次访问随机前缀」模式：每个访客拿到不同的落地子域。
func RandomSubLabel() string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	n := 7 + rand.Intn(4) // 总长 8~11（首字母另计）
	b := make([]byte, 1+n)
	b[0] = byte('a' + rand.Intn(26)) // DNS 标签习惯用字母开头
	for i := 1; i < len(b); i++ {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}

// matchList 判断 "CN,HK" / "*" 这类逗号列表是否命中所给值（不区分大小写）。
func matchList(list, value string) bool {
	list = strings.TrimSpace(list)
	if list == "" || list == "*" {
		return true
	}
	value = strings.ToLower(value)
	for _, part := range strings.Split(list, ",") {
		if strings.ToLower(strings.TrimSpace(part)) == value {
			return true
		}
	}
	return false
}

// Select 从候选 offer 中按 campaign/设备/国家/渠道匹配，优先级高者优先，同级按权重随机。
func Select(offers []store.Offer, v Visitor, campaign string) *store.Offer {
	var matched []store.Offer
	for _, o := range offers {
		if !o.Enabled {
			continue
		}
		if o.Campaign != campaign {
			continue
		}
		if !matchList(o.Device, v.Device) {
			continue
		}
		if !matchList(o.Country, v.Country) {
			continue
		}
		if !matchList(o.Channel, v.Channel) {
			continue
		}
		matched = append(matched, o)
	}
	if len(matched) == 0 {
		return nil
	}
	// 取最高优先级的一组
	maxP := matched[0].Priority
	for _, o := range matched {
		if o.Priority > maxP {
			maxP = o.Priority
		}
	}
	var top []store.Offer
	total := 0
	for _, o := range matched {
		if o.Priority == maxP {
			w := o.Weight
			if w < 1 {
				w = 1
			}
			top = append(top, o)
			total += w
		}
	}
	if len(top) == 1 || total <= 0 {
		return &top[0]
	}
	n := rand.Intn(total)
	acc := 0
	for i := range top {
		w := top[i].Weight
		if w < 1 {
			w = 1
		}
		acc += w
		if n < acc {
			return &top[i]
		}
	}
	return &top[len(top)-1]
}

// BuildClick 用访客上下文 + 命中的 offer 组装一条点击记录。
func BuildClick(v Visitor, offer *store.Offer, campaign string, r *http.Request, shareID int64) store.Click {
	c := store.Click{
		Host:      v.Host,
		Campaign:  campaign,
		Device:    v.Device,
		Country:   v.Country,
		Channel:   v.Channel,
		UTMSource: v.UTMSource,
		UTMMedium: v.UTMMedium,
		Referer:   v.Referer,
		UA:        v.UA,
		IPHash:    hashIP(clientIP(r)),
		Bot:       v.Bot,
		ShareID:   shareID,
	}
	if offer != nil {
		c.OfferID = offer.ID
		c.OfferName = offer.Name
	}
	return c
}
