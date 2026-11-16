package main

import (
	"fmt"
	"net/http"
)

// expiredPage 渲染一个简洁的「链接无效/已过期」提示页。
func expiredPage(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>链接已失效</title>
<style>*{box-sizing:border-box;margin:0;padding:0}html,body{height:100%%;background:#0d1520;font-family:-apple-system,"PingFang SC",sans-serif}
body{display:flex;align-items:center;justify-content:center}
.card{background:#131c27;border-radius:18px;padding:44px 28px;max-width:360px;text-align:center;box-shadow:0 8px 40px rgba(0,0,0,.5)}
.icon{font-size:46px}.title{color:#e6b74a;font-size:19px;font-weight:700;margin:14px 0 10px}
.desc{color:#8a9bb0;font-size:14px;line-height:1.7}</style></head>
<body><div class="card"><div class="icon">&#9203;</div><div class="title">%s</div>
<p class="desc">该链接已失效或不可用。请向你获取链接的渠道重新获取最新地址。</p></div></body></html>`, msg)
}
