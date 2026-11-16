// Package admin 提供后台管理面板：登录、域名/落地页/分享链接管理、点击统计、改密。
package admin

import (
	"crypto/rand"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"stemys/dispatch/internal/dispatch"
	"stemys/dispatch/internal/sign"
	"stemys/dispatch/internal/store"
)

//go:embed templates/*.html
var tmplFS embed.FS

//go:embed static
var staticFS embed.FS

type session struct {
	adminID  int64
	username string
	exp      time.Time
}

type Admin struct {
	db     *store.DB
	secret string
	mu     sync.RWMutex
	sess   map[string]session
}

func New(db *store.DB, secret string) *Admin {
	a := &Admin{db: db, secret: secret, sess: map[string]session{}}
	a.ensureDefaultAdmin()
	go a.gcSessions()
	return a
}

func (a *Admin) ensureDefaultAdmin() {
	n, err := a.db.CountAdmins()
	if err != nil {
		log.Printf("[admin] 检查管理员失败: %v", err)
		return
	}
	if n == 0 {
		hash, _ := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
		if err := a.db.CreateAdmin("admin", string(hash)); err != nil {
			log.Printf("[admin] 创建默认管理员失败: %v", err)
			return
		}
		log.Printf("[admin] 已创建默认管理员 admin / admin123 —— 请登录后立即修改密码！")
	}
}

func (a *Admin) gcSessions() {
	for {
		time.Sleep(10 * time.Minute)
		now := time.Now()
		a.mu.Lock()
		for k, s := range a.sess {
			if now.After(s.exp) {
				delete(a.sess, k)
			}
		}
		a.mu.Unlock()
	}
}

// ---- 会话 ----

func newSID() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (a *Admin) setSession(w http.ResponseWriter, adminID int64, username string) {
	sid := newSID()
	a.mu.Lock()
	a.sess[sid] = session{adminID: adminID, username: username, exp: time.Now().Add(12 * time.Hour)}
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "disp_sid", Value: sid, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 12 * 3600})
}

func (a *Admin) current(r *http.Request) (session, bool) {
	c, err := r.Cookie("disp_sid")
	if err != nil {
		return session{}, false
	}
	a.mu.RLock()
	s, ok := a.sess[c.Value]
	a.mu.RUnlock()
	if !ok || time.Now().After(s.exp) {
		return session{}, false
	}
	return s, true
}

func (a *Admin) clearSession(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("disp_sid"); err == nil {
		a.mu.Lock()
		delete(a.sess, c.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "disp_sid", Value: "", Path: "/", MaxAge: -1})
}

// ---- 视图 ----

type view struct {
	Title string
	Admin string
	Flash string
	Error string
	Page  any
}

func (a *Admin) render(w http.ResponseWriter, page string, v view) {
	t, err := template.New("layout").Funcs(funcs).ParseFS(tmplFS, "templates/layout.html", "templates/"+page)
	if err != nil {
		http.Error(w, "模板错误: "+err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "layout", v); err != nil {
		log.Printf("[admin] 渲染 %s 失败: %v", page, err)
	}
}

var funcs = template.FuncMap{
	"fmtTime": func(t time.Time) string { return t.Local().Format("2006-01-02 15:04:05") },
	"deref": func(p *int64) int64 {
		if p == nil {
			return 0
		}
		return *p
	},
	"arr":            func(xs ...string) []string { return xs },
	"devLabel":       devLabel,
	"countryLabelZH": countryLabelZH,
	"channelLabelZH": channelLabelZH,
	"ipClassZH":      ipClassZH,
	"stickyLabelZH":  stickyLabelZH,
}

// ---- 路由 ----

func (a *Admin) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/static/", a.serveStatic)

	mux.HandleFunc("/admin/login", a.loginPage)
	mux.HandleFunc("/admin/logout", a.logout)

	mux.Handle("/admin/", a.auth(http.HandlerFunc(a.index)))
	mux.Handle("/admin/dashboard", a.auth(http.HandlerFunc(a.dashboard)))
	mux.Handle("/admin/domains", a.auth(http.HandlerFunc(a.domains)))
	mux.Handle("/admin/domains/save", a.auth(http.HandlerFunc(a.domainsSave)))
	mux.Handle("/admin/domains/delete", a.auth(http.HandlerFunc(a.domainsDelete)))
	mux.Handle("/admin/domains/bulk", a.auth(http.HandlerFunc(a.domainsBulk)))
	mux.Handle("/admin/offers", a.auth(http.HandlerFunc(a.offers)))
	mux.Handle("/admin/offers/save", a.auth(http.HandlerFunc(a.offersSave)))
	mux.Handle("/admin/offers/delete", a.auth(http.HandlerFunc(a.offersDelete)))
	mux.Handle("/admin/shares", a.auth(http.HandlerFunc(a.shares)))
	mux.Handle("/admin/shares/create", a.auth(http.HandlerFunc(a.sharesCreate)))
	mux.Handle("/admin/shares/toggle", a.auth(http.HandlerFunc(a.sharesToggle)))
	mux.Handle("/admin/shares/delete", a.auth(http.HandlerFunc(a.sharesDelete)))
	mux.Handle("/admin/clicks", a.auth(http.HandlerFunc(a.clicks)))
	mux.Handle("/admin/settings", a.auth(http.HandlerFunc(a.settings)))
	mux.Handle("/admin/settings/anti", a.auth(http.HandlerFunc(a.settingsAnti)))
	mux.Handle("/admin/settings/carrier", a.auth(http.HandlerFunc(a.settingsCarrier)))
	mux.Handle("/admin/settings/password", a.auth(http.HandlerFunc(a.settingsPassword)))
	return mux
}

func (a *Admin) serveStatic(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/admin/static/")
	b, err := staticFS.ReadFile("static/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ct := "text/plain; charset=utf-8"
	if strings.HasSuffix(name, ".css") {
		ct = "text/css; charset=utf-8"
	} else if strings.HasSuffix(name, ".js") {
		ct = "application/javascript; charset=utf-8"
	}
	w.Header().Set("Content-Type", ct)
	w.Write(b)
}

func (a *Admin) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := a.current(r); !ok {
			http.Redirect(w, r, "/admin/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *Admin) loginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.current(r); ok {
		http.Redirect(w, r, "/admin/dashboard", http.StatusFound)
		return
	}
	if r.Method == http.MethodPost {
		u := strings.TrimSpace(r.FormValue("username"))
		p := r.FormValue("password")
		adm, err := a.db.GetAdmin(u)
		if err == nil && adm != nil && bcrypt.CompareHashAndPassword([]byte(adm.PassHash), []byte(p)) == nil {
			a.setSession(w, adm.ID, adm.Username)
			http.Redirect(w, r, "/admin/dashboard", http.StatusFound)
			return
		}
		a.render(w, "login.html", view{Title: "登录", Error: "用户名或密码错误"})
		return
	}
	a.render(w, "login.html", view{Title: "登录"})
}

func (a *Admin) logout(w http.ResponseWriter, r *http.Request) {
	a.clearSession(w, r)
	http.Redirect(w, r, "/admin/login", http.StatusFound)
}

func (a *Admin) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/admin/" && r.URL.Path != "/admin" {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/admin/dashboard", http.StatusFound)
}

// ---- 仪表盘 ----

func (a *Admin) dashboard(w http.ResponseWriter, r *http.Request) {
	s, _ := a.current(r)
	days := 7
	if d, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && d >= 1 && d <= 90 {
		days = d
	}
	st, err := a.db.StatsOverview(days)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	recent, _ := a.db.RecentClicks(30)
	a.render(w, "dashboard.html", view{
		Title: "概览", Admin: s.username, Page: map[string]any{
			"Days": days, "Stats": st, "Recent": recent,
			"HumanRate": pct(st.Human, st.Total),
		},
	})
}

func (a *Admin) clicks(w http.ResponseWriter, r *http.Request) {
	s, _ := a.current(r)
	rows, _ := a.db.RecentClicks(200)
	a.render(w, "clicks.html", view{Title: "点击明细", Admin: s.username, Page: rows})
}

// ---- 域名 ----

func (a *Admin) domains(w http.ResponseWriter, r *http.Request) {
	s, _ := a.current(r)
	list, _ := a.db.ListDomains()
	edit := &store.Domain{Enabled: true}
	if id, err := strconv.ParseInt(r.URL.Query().Get("edit"), 10, 64); err == nil {
		for _, d := range list {
			if d.ID == id {
				edit = &d
			}
		}
	}
	a.render(w, "domains.html", view{Title: "域名", Admin: s.username, Flash: r.URL.Query().Get("ok"),
		Page: map[string]any{"List": list, "Edit": edit}})
}

func (a *Admin) domainsSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/domains", http.StatusFound)
		return
	}
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	d := &store.Domain{
		ID:       id,
		Host:     strings.ToLower(strings.TrimSpace(r.FormValue("host"))),
		Campaign: strings.TrimSpace(r.FormValue("campaign")),
		Enabled:  r.FormValue("enabled") == "on",
	}
	if d.Host == "" {
		http.Redirect(w, r, "/admin/domains?ok=域名不能为空", http.StatusFound)
		return
	}
	if err := a.db.UpsertDomain(d); err != nil {
		http.Redirect(w, r, "/admin/domains?ok=保存失败:"+err.Error(), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/domains?ok=已保存", http.StatusFound)
}

func (a *Admin) domainsDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	_ = a.db.DeleteDomain(id)
	http.Redirect(w, r, "/admin/domains?ok=已删除", http.StatusFound)
}

// domainsBulk 批量导入入口域名池：每行 "域名 [campaign]" 或 "域名,campaign"。
// 已存在的域名跳过（不覆盖既有配置）。
func (a *Admin) domainsBulk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/domains", http.StatusFound)
		return
	}
	defaultCampaign := strings.TrimSpace(r.FormValue("campaign"))
	added, skipped := 0, 0
	for _, line := range strings.Split(r.FormValue("hosts"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		host, campaign := line, defaultCampaign
		if i := strings.IndexAny(line, " ,	"); i >= 0 {
			host = strings.TrimSpace(line[:i])
			if c := strings.TrimSpace(line[i+1:]); c != "" {
				campaign = c
			}
		}
		host = strings.ToLower(strings.TrimPrefix(host, "https://"))
		host = strings.ToLower(strings.TrimPrefix(host, "http://"))
		host = strings.Trim(host, "/")
		if host == "" {
			continue
		}
		if exist, _ := a.db.GetDomainByHost(host); exist != nil {
			skipped++
			continue
		}
		if err := a.db.UpsertDomain(&store.Domain{Host: host, Campaign: campaign, Enabled: true}); err != nil {
			skipped++
			continue
		}
		added++
	}
	http.Redirect(w, r, "/admin/domains?ok=批量导入完成：新增 "+strconv.Itoa(added)+" 个，跳过 "+strconv.Itoa(skipped)+" 个", http.StatusFound)
}

// ---- 落地页 ----

// campaignOptions 由域名池动态生成 campaign 下拉选项：去重保序，label 标注代表域名方便辨认；
// 首项「通用」= campaign 空，承接未登记/已停用域名的流量；全部域名已停用的 campaign 会在 label 提示。
func campaignOptions(doms []store.Domain) []Opt {
	out := []Opt{{"", "通用（未登记 / 已停用域名的流量兜底承接）"}}
	seen := map[string]int{}
	camps := []string{}
	hosts := map[string][]string{}
	allOff := map[string]bool{}
	for _, d := range doms {
		if d.Campaign == "" {
			continue
		}
		if _, ok := seen[d.Campaign]; !ok {
			seen[d.Campaign] = len(camps)
			camps = append(camps, d.Campaign)
			allOff[d.Campaign] = !d.Enabled
		} else {
			allOff[d.Campaign] = allOff[d.Campaign] && !d.Enabled
		}
		hosts[d.Campaign] = append(hosts[d.Campaign], d.Host)
	}
	for _, c := range camps {
		h := hosts[c]
		show := h
		if len(show) > 2 {
			show = show[:2]
		}
		detail := strings.Join(show, " / ")
		if len(h) > 2 {
			detail += fmt.Sprintf(" 等%d个域名", len(h))
		}
		if allOff[c] {
			detail += " ·域名已全部停用"
		}
		out = append(out, Opt{c, c + "（" + detail + "）"})
	}
	return out
}

func (a *Admin) offers(w http.ResponseWriter, r *http.Request) {
	s, _ := a.current(r)
	list, _ := a.db.ListOffers()
	doms, _ := a.db.ListDomains()
	campaigns := campaignOptions(doms)
	edit := &store.Offer{Device: "any", Country: "*", Channel: "*", SubMode: "fixed", Weight: 1, Enabled: true}
	if id, err := strconv.ParseInt(r.URL.Query().Get("edit"), 10, 64); err == nil {
		for _, o := range list {
			if o.ID == id {
				edit = &o
			}
		}
	}
	a.render(w, "offers.html", view{Title: "落地页", Admin: s.username, Flash: r.URL.Query().Get("ok"),
		Page: map[string]any{
			"List": list, "Edit": edit,
			"DeviceOptions":  deviceOptions,
			"CountryOptions": countryOptions,
			"ChannelOptions": channelOptions,
			// 编辑值不在预设列表时给下拉框一个兜底选项，避免旧数据被覆盖丢失
			"CustomCountry":   customValueIfUnknown(countryOptions, edit.Country),
			"CustomChannel":   customValueIfUnknown(channelOptions, edit.Channel),
			"CampaignOptions": campaigns,
			"CustomCampaign":  customValueIfUnknown(campaigns, edit.Campaign) != "",
			"StickyOptions":   stickyOptions,
			"StickyTTLStr":    strconv.FormatInt(edit.StickyTTL, 10),
			"StickyOn":        edit.StickyTTL > 0,
			"CustomSticky":    edit.StickyTTL > 0 && customValueIfUnknown(stickyOptions, strconv.FormatInt(edit.StickyTTL, 10)) != "",
		}})
}

func (a *Admin) offersSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/offers", http.StatusFound)
		return
	}
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	weight, _ := strconv.Atoi(r.FormValue("weight"))
	priority, _ := strconv.Atoi(r.FormValue("priority"))
	if weight < 1 {
		weight = 1
	}
	// 落地有效期开关：关 = 每次访问重新随机（sticky_ttl=0）；开 = 取所选时长，未选/非法时默认 30 分钟
	stickyTTL := int64(0)
	if r.FormValue("sticky_on") == "on" {
		stickyTTL, _ = strconv.ParseInt(strings.TrimSpace(r.FormValue("sticky_ttl")), 10, 64)
		if stickyTTL <= 0 {
			stickyTTL = 1800
		}
	}
	base := strings.TrimSpace(r.FormValue("wildcard_base"))
	base = strings.TrimPrefix(base, "*.")
	base = strings.Trim(base, ".")
	o := &store.Offer{
		ID:       id,
		Name:     strings.TrimSpace(r.FormValue("name")),
		URL:      strings.TrimSpace(r.FormValue("url")),
		Campaign: strings.TrimSpace(r.FormValue("campaign")),
		Device:   def(strings.TrimSpace(r.FormValue("device")), "any"),
		Country:  def(strings.TrimSpace(r.FormValue("country")), "*"),
		Channel:  def(strings.TrimSpace(r.FormValue("channel")), "*"),
		Weight:   weight,
		Priority: priority,
		Enabled:  r.FormValue("enabled") == "on",

		WildcardBase: base,
		SubLabel:     strings.Trim(strings.TrimSpace(r.FormValue("sub_label")), "."),
		Path:         strings.TrimSpace(r.FormValue("path")),
		SubMode:      def(strings.TrimSpace(r.FormValue("sub_mode")), "fixed"),
		StickyTTL:    stickyTTL,
	}
	if o.Name == "" || (o.WildcardBase == "" && o.URL == "") {
		http.Redirect(w, r, "/admin/offers?ok=名称必填，且落地URL或泛域名至少填一个", http.StatusFound)
		return
	}
	if o.SubMode == "random" && o.WildcardBase == "" {
		http.Redirect(w, r, "/admin/offers?ok=每次访问随机前缀需要填写泛域名根", http.StatusFound)
		return
	}
	if err := a.db.UpsertOffer(o); err != nil {
		http.Redirect(w, r, "/admin/offers?ok=保存失败:"+err.Error(), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/offers?ok=已保存", http.StatusFound)
}

func (a *Admin) offersDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	_ = a.db.DeleteOffer(id)
	http.Redirect(w, r, "/admin/offers?ok=已删除", http.StatusFound)
}

// ---- 分享链接 ----

func (a *Admin) shares(w http.ResponseWriter, r *http.Request) {
	s, _ := a.current(r)
	list, _ := a.db.ListShareLinks()
	offers, _ := a.db.ListOffers()
	// 生成完整 URL 前缀（用当前访问域名，便于复制）
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	baseURL := scheme + "://" + r.Host
	a.render(w, "shares.html", view{Title: "分享链接", Admin: s.username, Flash: r.URL.Query().Get("ok"),
		Page: map[string]any{"List": list, "Offers": offers, "BaseURL": baseURL}})
}

func (a *Admin) sharesCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/shares", http.StatusFound)
		return
	}
	target := strings.TrimSpace(r.FormValue("target_url"))
	if target == "" {
		// 也可以从下拉选择 offer
		if oid, err := strconv.ParseInt(r.FormValue("offer_id"), 10, 64); err == nil && oid > 0 {
			if o, _ := a.db.GetOffer(oid); o != nil {
				if o.IsRandomSub() {
					target = o.LandingURLFor(dispatch.RandomSubLabel())
				} else {
					target = o.LandingURL()
				}
			}
		}
	}
	if target == "" {
		http.Redirect(w, r, "/admin/shares?ok=目标地址必填", http.StatusFound)
		return
	}
	ttlHours, _ := strconv.Atoi(r.FormValue("ttl_hours"))
	if ttlHours <= 0 {
		ttlHours = 72
	}
	maxClicks, _ := strconv.Atoi(r.FormValue("max_clicks"))
	// 先占位拿 ID，再生成绑定 ID 的签名 token
	sl := &store.ShareLink{
		TargetURL: target,
		Note:      strings.TrimSpace(r.FormValue("note")),
		MaxClicks: maxClicks,
		ExpiresAt: time.Now().Add(time.Duration(ttlHours) * time.Hour),
		Enabled:   true,
	}
	if err := a.db.CreateShareLink(sl); err != nil {
		http.Redirect(w, r, "/admin/shares?ok=创建失败:"+err.Error(), http.StatusFound)
		return
	}
	sl.Token = sign.Sign(a.secret, sl.ID, sl.ExpiresAt)
	if err := a.db.UpdateShareToken(sl.ID, sl.Token); err != nil {
		http.Redirect(w, r, "/admin/shares?ok=生成token失败:"+err.Error(), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/shares?ok=已创建", http.StatusFound)
}

func (a *Admin) sharesToggle(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	en := r.FormValue("enabled") == "true"
	_ = a.db.SetShareEnabled(id, en)
	http.Redirect(w, r, "/admin/shares?ok=已更新", http.StatusFound)
}

func (a *Admin) sharesDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	_ = a.db.DeleteShareLink(id)
	http.Redirect(w, r, "/admin/shares?ok=已删除", http.StatusFound)
}

// ---- 设置 ----

func (a *Admin) settings(w http.ResponseWriter, r *http.Request) {
	s, _ := a.current(r)
	a.render(w, "settings.html", view{Title: "设置", Admin: s.username, Flash: r.URL.Query().Get("ok"),
		Page: map[string]any{
			"AntiEnabled":  a.db.GetConfig("anti_crawl_enabled", "1") != "0",
			"CrawlerExtra": a.db.GetConfig("crawler_ua_extra", ""),
			"BlockCidrs":   a.db.GetConfig("blocker_cidrs", ""),
			"DecoyTitle":   a.db.GetConfig("decoy_title", ""),
			"DecoyBody":    a.db.GetConfig("decoy_body", ""),
			"CarrierMode":  a.db.GetConfig("carrier_gate", "observe"),
			"CarrierCidrs": a.db.GetConfig("carrier_cidrs", ""),
			"CarrierOpts":  carrierGateOptions,
		}})
}

// settingsAnti 保存防采集伪装配置。
// decoy_title 留空 = 使用内置多套模板随机轮换；填了则固定用自定义文案。
func (a *Admin) settingsAnti(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/settings", http.StatusFound)
		return
	}
	enabled := r.FormValue("anti_enabled") == "on"
	title := strings.TrimSpace(r.FormValue("decoy_title"))
	body := strings.TrimSpace(r.FormValue("decoy_body"))
	if title == "" && body != "" {
		title = "网站维护公告" // 只写了正文没写标题时给个默认标题
	}
	en := "1"
	if !enabled {
		en = "0"
	}
	_ = a.db.SetConfig("anti_crawl_enabled", en)
	_ = a.db.SetConfig("crawler_ua_extra", r.FormValue("crawler_ua_extra"))
	_ = a.db.SetConfig("blocker_cidrs", r.FormValue("blocker_cidrs"))
	_ = a.db.SetConfig("decoy_title", title)
	_ = a.db.SetConfig("decoy_body", body)
	http.Redirect(w, r, "/admin/settings?ok=防采集设置已保存", http.StatusFound)
}

// settingsCarrier 保存网络类型闸门（carrier_gate + carrier_cidrs）。
func (a *Admin) settingsCarrier(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/settings", http.StatusFound)
		return
	}
	mode := strings.TrimSpace(r.FormValue("carrier_mode"))
	switch mode {
	case "off", "observe", "strict":
	default:
		mode = "observe"
	}
	_ = a.db.SetConfig("carrier_gate", mode)
	_ = a.db.SetConfig("carrier_cidrs", r.FormValue("carrier_cidrs"))
	http.Redirect(w, r, "/admin/settings?ok=网络类型闸门已保存", http.StatusFound)
}

func (a *Admin) settingsPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/settings", http.StatusFound)
		return
	}
	s, _ := a.current(r)
	old := r.FormValue("old")
	nw := r.FormValue("new")
	if len(nw) < 6 {
		http.Redirect(w, r, "/admin/settings?ok=新密码至少6位", http.StatusFound)
		return
	}
	adm, err := a.db.GetAdmin(s.username)
	if err != nil || adm == nil || bcrypt.CompareHashAndPassword([]byte(adm.PassHash), []byte(old)) != nil {
		http.Redirect(w, r, "/admin/settings?ok=原密码错误", http.StatusFound)
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(nw), bcrypt.DefaultCost)
	_ = a.db.SetAdminPassword(adm.ID, string(hash))
	http.Redirect(w, r, "/admin/settings?ok=密码已修改", http.StatusFound)
}

// ---- 工具 ----

func def(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func pct(part, total int64) string {
	if total == 0 {
		return "0%"
	}
	return strconv.FormatFloat(float64(part)*100/float64(total), 'f', 1, 64) + "%"
}
