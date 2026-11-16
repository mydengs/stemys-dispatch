package main

import (
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"stemys/dispatch/internal/dispatch"
	"stemys/dispatch/internal/store"
)

// decoy.go —— 防采集伪装：爬虫/探测请求命中时返回中性的公告/简介类页面，
// 不给滑块验证页、不给 302 跳转链，避免厂商爬虫采集到入口的分发行为与落地域名池。
// 内置多套风格不同的模板随机轮换，消除"页面指纹"；后台自定义文案则固定用自定义单模板。

// splitLines 把后台多行文本按行拆成列表（忽略空行）。
func splitLines(text string) []string {
	parts := strings.Split(text, "\n")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// decoyEnabledAndCrawler 判定本次请求是否应走伪装页。
func decoyEnabledAndCrawler(db *store.DB, r *http.Request) (enabled bool, crawler bool) {
	enabled = db.GetConfig("anti_crawl_enabled", "1") != "0"
	if !enabled {
		return
	}
	extra := splitLines(db.GetConfig("crawler_ua_extra", ""))
	cidrs := dispatch.ParseCIDRs(splitLines(db.GetConfig("blocker_cidrs", "")))
	crawler = dispatch.IsCrawler(r, extra, cidrs)
	return
}

// decoyDate 生成带随机感的日期时间文案（回拨 0~72h，更像真实发布时间）。
func decoyDate() string {
	t := time.Now()
	if rand.Intn(2) == 0 {
		t = t.Add(-time.Duration(rand.Intn(72)) * time.Hour)
	}
	return fmt.Sprintf("%d年%02d月%02d日 %02d:%02d", t.Year(), int(t.Month()), t.Day(), t.Hour(), t.Minute())
}

const decoySharedCSS = `*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,"PingFang SC",sans-serif;color:#333}a{color:#06c;text-decoration:none}`

// decoyTemplates 内置的中性页面模板组：布局/配色/文案结构互不相同，按请求随机轮换。
// 参数：%[1]s=标题，%[2]s=日期。
var decoyTemplates = []struct {
	title string
	html  string
}{
	{"网站维护公告", `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>%[1]s</title><style>` + decoySharedCSS + `body{background:#f7f8fa;display:flex;align-items:center;justify-content:center;min-height:100vh}.box{max-width:520px;width:92%%;background:#fff;border:1px solid #e3e6ea;border-radius:12px;padding:44px 36px;text-align:center}h1{font-size:20px;font-weight:600;margin-bottom:14px}p{font-size:14px;line-height:1.8;color:#666}.t{margin-top:22px;font-size:12px;color:#aaa}</style></head><body><div class="box"><h1>%[1]s</h1><p>系统正在维护升级中，预计稍后恢复访问。给您带来的不便敬请谅解。</p><div class="t">%[2]s</div></div></body></html>`},

	{"系统升级通知", `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>%[1]s</title><style>` + decoySharedCSS + `body{background:#fff}.wrap{max-width:680px;margin:0 auto;padding:56px 24px}nav{margin-bottom:30px;font-size:13px;color:#999}nav b{color:#c00}h1{font-size:22px;font-weight:600;border-bottom:1px solid #eee;padding-bottom:14px}p{font-size:15px;line-height:2;color:#444;margin:16px 0}.t{font-size:12px;color:#999}</style></head><body><div class="wrap"><nav><b>通知</b> · 中心</nav><h1>%[1]s</h1><p>为提升服务质量，我们对平台基础设施进行例行升级维护。期间部分功能可能暂时无法访问，维护完成后将自动恢复正常。</p><p>感谢您的理解与支持。</p><div class="t">发布：%[2]s</div></div></body></html>`},

	{"站点信息", `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>%[1]s</title><style>` + decoySharedCSS + `body{background:#fff}.hd{border-bottom:1px solid #eee;padding:18px 24px;font-size:17px;font-weight:600}.wrap{max-width:720px;margin:0 auto;padding:38px 24px}.row{display:flex;border-bottom:1px solid #f2f2f2;padding:13px 2px;font-size:14px}.k{width:110px;color:#888}.foot{margin-top:28px;font-size:12px;color:#aaa;text-align:center}</style></head><body><div class="hd">站点信息</div><div class="wrap"><div class="row"><div class="k">站点状态</div><div>运行正常</div></div><div class="row"><div class="k">服务时间</div><div>工作日 9:00–18:00</div></div><div class="row"><div class="k">最近更新</div><div>%[2]s</div></div><div class="foot">本页面仅供参考 · %[2]s</div></div></body></html>`},

	{"资讯速览", `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>%[1]s</title><style>` + decoySharedCSS + `body{background:#fbfbfb}.wrap{max-width:640px;margin:0 auto;padding:44px 20px}h1{font-size:18px;margin-bottom:20px}.item{background:#fff;border:1px solid #eee;border-radius:8px;padding:16px 18px;margin-bottom:12px}.item h3{font-size:15px;font-weight:600;margin-bottom:6px}.item p{font-size:13px;color:#777;line-height:1.7}.d{font-size:12px;color:#bbb;margin-top:8px}</style></head><body><div class="wrap"><h1>资讯速览</h1><div class="item"><h3>行业资讯更新</h3><p>更多内容整理中，请稍后再来查看最新动态。</p><div class="d">%[2]s</div></div><div class="item"><h3>服务公告</h3><p>平台服务运行正常，如遇访问异常请稍候刷新重试。</p><div class="d">%[2]s</div></div></div></body></html>`},
}

// serveDecoy 返回中性伪装页（200，无跳转、无业务信息、noindex）。
// 后台设置过 decoy_title 时用自定义单模板；未设置则内置模板随机轮换。
func serveDecoy(w http.ResponseWriter, db *store.DB) {
	customTitle := db.GetConfig("decoy_title", "")
	customBody := strings.TrimSpace(db.GetConfig("decoy_body", ""))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")

	if customTitle != "" {
		body := customBody
		if body == "" {
			body = "系统正在维护升级中，预计稍后恢复访问。给您带来的不便敬请谅解。"
		}
		fmt.Fprintf(w, `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>%s</title><style>`+decoySharedCSS+`body{background:#f7f8fa;display:flex;align-items:center;justify-content:center;min-height:100vh}.box{max-width:520px;width:92%%;background:#fff;border:1px solid #e3e6ea;border-radius:12px;padding:44px 36px;text-align:center}h1{font-size:20px;font-weight:600;margin-bottom:14px}p{font-size:14px;line-height:1.8;color:#666}.t{margin-top:22px;font-size:12px;color:#aaa}</style></head><body><div class="box"><h1>%s</h1><p>%s</p><div class="t">%s</div></div></body></html>`,
			customTitle, customTitle, body, decoyDate())
		return
	}
	t := decoyTemplates[rand.Intn(len(decoyTemplates))]
	fmt.Fprintf(w, t.html, t.title, decoyDate())
}

// logDecoyHit 记录一次爬虫命中（landing=decoy，bot 标记，附带网络类型）。
func logDecoyHit(db *store.DB, v dispatch.Visitor, r *http.Request, ipcls string) {
	c := dispatch.BuildClick(v, nil, "", r, 0)
	c.Bot = true
	c.Landing = "decoy"
	c.IPClass = ipcls
	_ = db.InsertClick(&c)
}
