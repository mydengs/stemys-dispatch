// Package store 负责 SQLite 持久化：域、落地页(offer)、分流规则、点击日志、分享链接、管理员。
package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type DB struct{ *sql.DB }

// ---- 模型 ----

// Domain 一个承接域名，绑定到一个 campaign（活动）。
type Domain struct {
	ID       int64
	Host     string // 完整主机名，如 shop.example.com
	Campaign string // 所属活动标识
	Enabled  bool
	Created  time.Time
}

// Offer 落地页。匹配条件：campaign + 设备 + 国家 + 渠道，priority 高者优先，同优先级按权重随机。
type Offer struct {
	ID       int64
	Name     string
	URL      string
	Campaign string
	Device   string // any|mobile|desktop|tablet
	Country  string // * 或逗号分隔国家码，如 CN,HK
	Channel  string // * 或逗号分隔渠道，如 wechat,douyin
	Weight   int
	Priority int
	Enabled  bool
	Created  time.Time

	// 泛域名落地：设置 WildcardBase 后，落地地址 = https://<前缀>.<WildcardBase><Path>
	// 例：WildcardBase="a.b.com", 前缀="asfsdg112t", Path="/baidu"
	//     => https://asfsdg112t.a.b.com/baidu
	WildcardBase string // 泛域名根，如 a.b.com（可填 *.a.b.com，自动去掉 *.）
	SubLabel     string // 子域前缀标签（SubMode=fixed 时使用）
	Path         string // 落地路径，如 /baidu（可空）
	SubMode      string // fixed = 固定前缀；random = 每次访问现场随机生成新前缀（每个访客不同）
	StickyTTL    int64  // 随机前缀回访有效期（秒）：0=每次访问都换新；>0=有效期内同一用户回访沿用同一前缀（每次回访自动续期），超期才换新的
}

// LandingURLFor 用给定前缀拼出落地地址：https://<label>.<wildcard><path>。
// wildcard 为空时回退到 URL 字段。
func (o Offer) LandingURLFor(label string) string {
	base := strings.TrimSpace(o.WildcardBase)
	if base == "" {
		return strings.TrimSpace(o.URL)
	}
	base = strings.TrimPrefix(base, "*.")
	base = strings.TrimPrefix(base, ".")
	base = strings.Trim(base, ".")
	label = strings.Trim(strings.TrimSpace(label), ".")
	host := base
	if label != "" {
		host = label + "." + base
	}
	path := strings.TrimSpace(o.Path)
	if path != "" && !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return "https://" + host + path
}

// LandingURL 返回该 offer 对外跳转的落地地址。
// SubMode=random 时返回占位形式（真实前缀由分流层现场生成）。
func (o Offer) LandingURL() string {
	if o.WildcardBase != "" && o.SubMode == "random" {
		return o.LandingURLFor("<随机>")
	}
	return o.LandingURLFor(o.SubLabel)
}

// IsRandomSub 是否每次访问随机前缀模式。
func (o Offer) IsRandomSub() bool {
	return o.WildcardBase != "" && o.SubMode == "random"
}

// Click 一次点击/跳转记录。
type Click struct {
	ID        int64
	TS        time.Time
	Host      string
	Campaign  string
	OfferID   int64
	OfferName string
	Device    string
	Country   string
	Channel   string
	UTMSource string
	UTMMedium string
	Referer   string
	UA        string
	IPHash    string
	Bot       bool
	ShareID   int64  // 若来自分享链接
	Landing   string // 实际跳转的落地地址（随机前缀模式下每个访客不同）
	IPClass   string // 网络类型：carrier(运营商家宽/蜂窝)/other(白名单外)/deny(黑名单)；闸门关闭时为空
}

// ShareLink 带签名与有效期的分享链接。
type ShareLink struct {
	ID        int64
	Token     string
	TargetURL string
	Note      string
	MaxClicks int // 0 = 不限
	Clicks    int
	ExpiresAt time.Time
	Enabled   bool
	Created   time.Time
}

// Admin 后台账号。
type Admin struct {
	ID       int64
	Username string
	PassHash string
}

// ---- 打开 & 迁移 ----

func Open(path string) (*DB, error) {
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	sqldb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	sqldb.SetMaxOpenConns(1)
	db := &DB{sqldb}
	if err := db.migrate(); err != nil {
		return nil, err
	}
	return db, nil
}

func (d *DB) migrate() error {
	_, err := d.Exec(`
CREATE TABLE IF NOT EXISTS domains (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host TEXT NOT NULL UNIQUE,
  campaign TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS offers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  url TEXT NOT NULL,
  campaign TEXT NOT NULL DEFAULT '',
  device TEXT NOT NULL DEFAULT 'any',
  country TEXT NOT NULL DEFAULT '*',
  channel TEXT NOT NULL DEFAULT '*',
  weight INTEGER NOT NULL DEFAULT 1,
  priority INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1,
  created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  wildcard_base TEXT NOT NULL DEFAULT '',
  sub_label TEXT NOT NULL DEFAULT '',
  path TEXT NOT NULL DEFAULT '',
  sub_mode TEXT NOT NULL DEFAULT 'fixed',
  sticky_ttl INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS clicks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  host TEXT, campaign TEXT,
  offer_id INTEGER, offer_name TEXT,
  device TEXT, country TEXT, channel TEXT,
  utm_source TEXT, utm_medium TEXT,
  referer TEXT, ua TEXT, ip_hash TEXT,
  bot INTEGER NOT NULL DEFAULT 0,
  share_id INTEGER NOT NULL DEFAULT 0
, landing TEXT NOT NULL DEFAULT '', ip_class TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_clicks_ts ON clicks(ts);
CREATE TABLE IF NOT EXISTS share_links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token TEXT NOT NULL UNIQUE,
  target_url TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  max_clicks INTEGER NOT NULL DEFAULT 0,
  clicks INTEGER NOT NULL DEFAULT 0,
  expires_at TIMESTAMP NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  pass_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS site_config (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT ''
);
`)
	if err != nil {
		return err
	}
	// 兼容旧库：补齐新列（已存在则忽略错误）
	for _, col := range []string{
		"ALTER TABLE offers ADD COLUMN wildcard_base TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE offers ADD COLUMN sub_label TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE offers ADD COLUMN path TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE offers ADD COLUMN sub_mode TEXT NOT NULL DEFAULT 'fixed'",
		"ALTER TABLE clicks ADD COLUMN landing TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE clicks ADD COLUMN ip_class TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE offers ADD COLUMN sticky_ttl INTEGER NOT NULL DEFAULT 0",
	} {
		_, _ = d.Exec(col)
	}
	return nil
}

// ---- Domain ----

func (d *DB) ListDomains() ([]Domain, error) {
	rows, err := d.Query(`SELECT id,host,campaign,enabled,created FROM domains ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Domain
	for rows.Next() {
		var x Domain
		if err := rows.Scan(&x.ID, &x.Host, &x.Campaign, &x.Enabled, &x.Created); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func (d *DB) GetDomainByHost(host string) (*Domain, error) {
	var x Domain
	err := d.QueryRow(`SELECT id,host,campaign,enabled,created FROM domains WHERE host=?`, host).
		Scan(&x.ID, &x.Host, &x.Campaign, &x.Enabled, &x.Created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &x, err
}

// ResolveDomain 解析请求主机：先精确匹配，再匹配已登记的泛域名（*.abc.com）。
// 泛域名取后缀最长（最具体）的一条。
func (d *DB) ResolveDomain(host string) (*Domain, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	dom, err := d.GetDomainByHost(host)
	if err != nil || dom != nil {
		return dom, err
	}
	rows, err := d.Query(`SELECT id,host,campaign,enabled,created FROM domains WHERE host LIKE '*.%'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var best *Domain
	bestLen := -1
	for rows.Next() {
		var x Domain
		if err := rows.Scan(&x.ID, &x.Host, &x.Campaign, &x.Enabled, &x.Created); err != nil {
			return nil, err
		}
		suffix := strings.TrimPrefix(x.Host, "*") // 例如 ".abc.com"
		if strings.HasSuffix(host, suffix) && len(host) > len(suffix) && len(suffix) > bestLen {
			xx := x
			best = &xx
			bestLen = len(suffix)
		}
	}
	return best, rows.Err()
}

func (d *DB) UpsertDomain(x *Domain) error {
	if x.ID == 0 {
		res, err := d.Exec(`INSERT INTO domains(host,campaign,enabled) VALUES(?,?,?)`, x.Host, x.Campaign, x.Enabled)
		if err != nil {
			return err
		}
		x.ID, _ = res.LastInsertId()
		return nil
	}
	_, err := d.Exec(`UPDATE domains SET host=?,campaign=?,enabled=? WHERE id=?`, x.Host, x.Campaign, x.Enabled, x.ID)
	return err
}

func (d *DB) DeleteDomain(id int64) error {
	_, err := d.Exec(`DELETE FROM domains WHERE id=?`, id)
	return err
}

// ---- Offer ----

func (d *DB) ListOffers() ([]Offer, error) {
	rows, err := d.Query(`SELECT id,name,url,campaign,device,country,channel,weight,priority,enabled,created,wildcard_base,sub_label,path,sub_mode,sticky_ttl FROM offers ORDER BY priority DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Offer
	for rows.Next() {
		var x Offer
		if err := rows.Scan(&x.ID, &x.Name, &x.URL, &x.Campaign, &x.Device, &x.Country, &x.Channel, &x.Weight, &x.Priority, &x.Enabled, &x.Created, &x.WildcardBase, &x.SubLabel, &x.Path, &x.SubMode, &x.StickyTTL); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func (d *DB) GetOffer(id int64) (*Offer, error) {
	var x Offer
	err := d.QueryRow(`SELECT id,name,url,campaign,device,country,channel,weight,priority,enabled,created,wildcard_base,sub_label,path,sub_mode,sticky_ttl FROM offers WHERE id=?`, id).
		Scan(&x.ID, &x.Name, &x.URL, &x.Campaign, &x.Device, &x.Country, &x.Channel, &x.Weight, &x.Priority, &x.Enabled, &x.Created, &x.WildcardBase, &x.SubLabel, &x.Path, &x.SubMode, &x.StickyTTL)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &x, err
}

func (d *DB) UpsertOffer(x *Offer) error {
	if x.ID == 0 {
		if x.SubMode == "" {
			x.SubMode = "fixed"
		}
		res, err := d.Exec(`INSERT INTO offers(name,url,campaign,device,country,channel,weight,priority,enabled,wildcard_base,sub_label,path,sub_mode,sticky_ttl) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			x.Name, x.URL, x.Campaign, x.Device, x.Country, x.Channel, x.Weight, x.Priority, x.Enabled, x.WildcardBase, x.SubLabel, x.Path, x.SubMode, x.StickyTTL)
		if err != nil {
			return err
		}
		x.ID, _ = res.LastInsertId()
		return nil
	}
	if x.SubMode == "" {
		x.SubMode = "fixed"
	}
	_, err := d.Exec(`UPDATE offers SET name=?,url=?,campaign=?,device=?,country=?,channel=?,weight=?,priority=?,enabled=?,wildcard_base=?,sub_label=?,path=?,sub_mode=?,sticky_ttl=? WHERE id=?`,
		x.Name, x.URL, x.Campaign, x.Device, x.Country, x.Channel, x.Weight, x.Priority, x.Enabled, x.WildcardBase, x.SubLabel, x.Path, x.SubMode, x.StickyTTL, x.ID)
	return err
}

func (d *DB) DeleteOffer(id int64) error {
	_, err := d.Exec(`DELETE FROM offers WHERE id=?`, id)
	return err
}

// ActiveOffers 只取启用的，供分流引擎使用。
func (d *DB) ActiveOffers() ([]Offer, error) {
	rows, err := d.Query(`SELECT id,name,url,campaign,device,country,channel,weight,priority,enabled,created,wildcard_base,sub_label,path,sub_mode,sticky_ttl FROM offers WHERE enabled=1 ORDER BY priority DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Offer
	for rows.Next() {
		var x Offer
		if err := rows.Scan(&x.ID, &x.Name, &x.URL, &x.Campaign, &x.Device, &x.Country, &x.Channel, &x.Weight, &x.Priority, &x.Enabled, &x.Created, &x.WildcardBase, &x.SubLabel, &x.Path, &x.SubMode, &x.StickyTTL); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// ---- Click ----

func (d *DB) InsertClick(c *Click) error {
	res, err := d.Exec(`INSERT INTO clicks(host,campaign,offer_id,offer_name,device,country,channel,utm_source,utm_medium,referer,ua,ip_hash,bot,share_id,landing,ip_class)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		c.Host, c.Campaign, c.OfferID, c.OfferName, c.Device, c.Country, c.Channel,
		c.UTMSource, c.UTMMedium, c.Referer, c.UA, c.IPHash, c.Bot, c.ShareID, c.Landing, c.IPClass)
	if err != nil {
		return err
	}
	c.ID, _ = res.LastInsertId()
	return nil
}

// StatsOverview 聚合近 n 天的关键指标。
type StatsOverview struct {
	Total     int64
	Human     int64
	Bot       int64
	ByDevice  map[string]int64
	ByCountry map[string]int64
	ByChannel map[string]int64
	ByDay     map[string]int64
	ByOffer   map[string]int64
}

func (d *DB) StatsOverview(days int) (*StatsOverview, error) {
	o := &StatsOverview{ByDevice: map[string]int64{}, ByCountry: map[string]int64{}, ByChannel: map[string]int64{}, ByDay: map[string]int64{}, ByOffer: map[string]int64{}}
	since := time.Now().AddDate(0, 0, -days).Format("2006-01-02 15:04:05")

	if err := d.QueryRow(`SELECT COUNT(*), COALESCE(SUM(CASE WHEN bot=0 THEN 1 ELSE 0 END),0), COALESCE(SUM(bot),0) FROM clicks WHERE ts>=?`, since).
		Scan(&o.Total, &o.Human, &o.Bot); err != nil {
		return nil, err
	}
	group := func(q string, dst map[string]int64) error {
		rows, err := d.Query(q, since)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k string
			var v int64
			if err := rows.Scan(&k, &v); err != nil {
				return err
			}
			dst[k] = v
		}
		return rows.Err()
	}
	if err := group(`SELECT COALESCE(device,''),COUNT(*) FROM clicks WHERE ts>=? GROUP BY device ORDER BY 2 DESC`, o.ByDevice); err != nil {
		return nil, err
	}
	if err := group(`SELECT COALESCE(country,''),COUNT(*) FROM clicks WHERE ts>=? GROUP BY country ORDER BY 2 DESC`, o.ByCountry); err != nil {
		return nil, err
	}
	if err := group(`SELECT COALESCE(channel,''),COUNT(*) FROM clicks WHERE ts>=? GROUP BY channel ORDER BY 2 DESC`, o.ByChannel); err != nil {
		return nil, err
	}
	if err := group(`SELECT substr(ts,1,10),COUNT(*) FROM clicks WHERE ts>=? GROUP BY 1 ORDER BY 1`, o.ByDay); err != nil {
		return nil, err
	}
	if err := group(`SELECT COALESCE(offer_name,''),COUNT(*) FROM clicks WHERE ts>=? GROUP BY offer_name ORDER BY 2 DESC`, o.ByOffer); err != nil {
		return nil, err
	}
	return o, nil
}

func (d *DB) RecentClicks(limit int) ([]Click, error) {
	rows, err := d.Query(`SELECT id,ts,host,campaign,offer_id,offer_name,device,country,channel,utm_source,utm_medium,referer,ua,ip_hash,bot,share_id,landing,ip_class
		FROM clicks ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Click
	for rows.Next() {
		var c Click
		if err := rows.Scan(&c.ID, &c.TS, &c.Host, &c.Campaign, &c.OfferID, &c.OfferName, &c.Device, &c.Country, &c.Channel, &c.UTMSource, &c.UTMMedium, &c.Referer, &c.UA, &c.IPHash, &c.Bot, &c.ShareID, &c.Landing, &c.IPClass); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ---- ShareLink ----

func (d *DB) ListShareLinks() ([]ShareLink, error) {
	rows, err := d.Query(`SELECT id,token,target_url,note,max_clicks,clicks,expires_at,enabled,created FROM share_links ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ShareLink
	for rows.Next() {
		var x ShareLink
		if err := rows.Scan(&x.ID, &x.Token, &x.TargetURL, &x.Note, &x.MaxClicks, &x.Clicks, &x.ExpiresAt, &x.Enabled, &x.Created); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func (d *DB) GetShareByToken(token string) (*ShareLink, error) {
	var x ShareLink
	err := d.QueryRow(`SELECT id,token,target_url,note,max_clicks,clicks,expires_at,enabled,created FROM share_links WHERE token=?`, token).
		Scan(&x.ID, &x.Token, &x.TargetURL, &x.Note, &x.MaxClicks, &x.Clicks, &x.ExpiresAt, &x.Enabled, &x.Created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &x, err
}

func (d *DB) CreateShareLink(x *ShareLink) error {
	res, err := d.Exec(`INSERT INTO share_links(token,target_url,note,max_clicks,clicks,expires_at,enabled) VALUES(?,?,?,?,?,?,?)`,
		x.Token, x.TargetURL, x.Note, x.MaxClicks, x.Clicks, x.ExpiresAt, x.Enabled)
	if err != nil {
		return err
	}
	x.ID, _ = res.LastInsertId()
	return nil
}

func (d *DB) UpdateShareToken(id int64, token string) error {
	_, err := d.Exec(`UPDATE share_links SET token=? WHERE id=?`, token, id)
	return err
}

func (d *DB) IncShareClicks(id int64) error {
	_, err := d.Exec(`UPDATE share_links SET clicks=clicks+1 WHERE id=?`, id)
	return err
}

func (d *DB) SetShareEnabled(id int64, enabled bool) error {
	_, err := d.Exec(`UPDATE share_links SET enabled=? WHERE id=?`, enabled, id)
	return err
}

func (d *DB) DeleteShareLink(id int64) error {
	_, err := d.Exec(`DELETE FROM share_links WHERE id=?`, id)
	return err
}

// ---- Admin ----

func (d *DB) GetAdmin(username string) (*Admin, error) {
	var a Admin
	err := d.QueryRow(`SELECT id,username,pass_hash FROM admins WHERE username=?`, username).
		Scan(&a.ID, &a.Username, &a.PassHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &a, err
}

func (d *DB) CountAdmins() (int64, error) {
	var n int64
	err := d.QueryRow(`SELECT COUNT(*) FROM admins`).Scan(&n)
	return n, err
}

func (d *DB) CreateAdmin(username, hash string) error {
	_, err := d.Exec(`INSERT INTO admins(username,pass_hash) VALUES(?,?)`, username, hash)
	return err
}

func (d *DB) SetAdminPassword(id int64, hash string) error {
	_, err := d.Exec(`UPDATE admins SET pass_hash=? WHERE id=?`, hash, id)
	return err
}

// ---- site_config（KV 配置：防采集伪装等运行期可调项） ----

// GetConfig 读取一个 KV 配置，missing 返回 def。
func (d *DB) GetConfig(key, def string) string {
	var v string
	err := d.QueryRow(`SELECT value FROM site_config WHERE key=?`, key).Scan(&v)
	if err != nil || v == "" {
		return def
	}
	return v
}

// SetConfig 写入一个 KV 配置。
func (d *DB) SetConfig(key, value string) error {
	_, err := d.Exec(`INSERT INTO site_config(key,value) VALUES(?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}
