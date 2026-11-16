package admin

import (
	"strconv"
	"strings"
)

// 后台 UI 的中文选项与中文显示映射。
// 数据库与分流引擎内部仍使用英文代码（mobile / CN / wechat ...），此处只做展示层翻译。

type Opt struct {
	Value string
	Label string
}

var deviceOptions = []Opt{
	{"any", "不限设备"},
	{"mobile", "手机（移动端）"},
	{"tablet", "平板"},
	{"desktop", "电脑（桌面端）"},
}

var countryOptions = []Opt{
	{"*", "不限（全球）"},
	{"CN", "中国大陆"},
	{"HK", "中国香港"},
	{"TW", "中国台湾"},
	{"MO", "中国澳门"},
	{"SG", "新加坡"},
	{"MY", "马来西亚"},
	{"TH", "泰国"},
	{"VN", "越南"},
	{"PH", "菲律宾"},
	{"ID", "印度尼西亚"},
	{"JP", "日本"},
	{"KR", "韩国"},
	{"IN", "印度"},
	{"US", "美国"},
	{"CA", "加拿大"},
	{"GB", "英国"},
	{"DE", "德国"},
	{"FR", "法国"},
	{"ES", "西班牙"},
	{"IT", "意大利"},
	{"NL", "荷兰"},
	{"RU", "俄罗斯"},
	{"UA", "乌克兰"},
	{"TR", "土耳其"},
	{"EG", "埃及"},
	{"NG", "尼日利亚"},
	{"ZA", "南非"},
	{"AU", "澳大利亚"},
	{"NZ", "新西兰"},
	{"BR", "巴西"},
	{"MX", "墨西哥"},
	{"AR", "阿根廷"},
	{"ZZ", "未知地区"},
}

var channelOptions = []Opt{
	{"*", "不限渠道"},
	{"wechat", "微信"},
	{"qq", "QQ"},
	{"douyin", "抖音 / 巨量"},
	{"toutiao", "今日头条"},
	{"kuaishou", "快手"},
	{"baidu", "百度"},
	{"google", "Google"},
	{"facebook", "Facebook"},
	{"telegram", "Telegram"},
	{"direct", "直接访问"},
}

var (
	deviceLabels  = toMap(deviceOptions)
	countryLabels = toMap(countryOptions)
	channelLabels = toMap(channelOptions)
)

// carrierGateOptions 网络类型闸门的三种模式。
var carrierGateOptions = []Opt{
	{"off", "关闭（不判定网络类型）"},
	{"observe", "观察（仅记录分类，放行行为不变）"},
	{"strict", "严格（仅运营商网络放行，白名单外一律伪装页）"},
}

// stickyOptions 落地地址有效时长的预设值（秒，字符串形态供下拉框 value；开关关闭即「每次重新随机」，不在表内）。
var stickyOptions = []Opt{
	{"1800", "30 分钟"},
	{"3600", "1 小时"},
	{"10800", "3 小时"},
	{"14400", "4 小时"},
	{"28800", "8 小时"},
	{"43200", "12 小时"},
	{"86400", "24 小时"},
	{"259200", "3 天"},
	{"604800", "7 天"},
}

// stickyLabelZH 把有效期秒数翻译成人话（供列表展示；不在预设表里的显示 N 秒）。
func stickyLabelZH(ttl int64) string {
	if ttl <= 0 {
		return "不固定"
	}
	for _, o := range stickyOptions {
		if o.Value == strconv.FormatInt(ttl, 10) {
			return o.Label
		}
	}
	return strconv.FormatInt(ttl, 10) + " 秒"
}

// ipClassLabels 点击明细「网络类型」列的显示文案。
var ipClassLabels = map[string]string{
	"carrier": "运营商网络（家宽/蜂窝）",
	"other":   "白名单外（云/专线/教育/VPN）",
	"deny":    "命中机房黑名单",
}

// ipClassZH 把存储的网络类型代码翻译成中文（空=「-」，未知值原样显示）。
func ipClassZH(v string) string {
	if l, ok := ipClassLabels[v]; ok {
		return l
	}
	if v == "" {
		return "-"
	}
	return v
}

func trimAll(v string) string { return strings.TrimSpace(v) }

// splitList 拆分 "CN,US" 这类逗号列表并清理空白。
func splitList(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func toMap(opts []Opt) map[string]string {
	m := make(map[string]string, len(opts))
	for _, o := range opts {
		m[o.Value] = o.Label
	}
	return m
}

// devLabel 设备中文名。
func devLabel(v string) string {
	if s, ok := deviceLabels[v]; ok {
		return s
	}
	return v
}

// listLabelZH 把逗号分隔的英文代码列表翻译为中文（保持原样跳过未知项）。
func listLabelZH(v string, dict map[string]string) string {
	v = trimAll(v)
	if v == "" {
		return "不限"
	}
	out := ""
	for _, part := range splitList(v) {
		label := part
		if s, ok := dict[part]; ok {
			label = s
		}
		if out == "" {
			out = label
		} else {
			out += "、" + label
		}
	}
	return out
}

func countryLabelZH(v string) string { return listLabelZH(v, countryLabels) }
func channelLabelZH(v string) string {
	s := listLabelZH(v, channelLabels)
	if s == "不限" {
		return "不限渠道"
	}
	return s
}

func inOptions(opts []Opt, value string) bool {
	_, ok := dictOf(opts)[value]
	return ok
}

func dictOf(opts []Opt) map[string]string { return toMap(opts) }

// customValueIfUnknown 编辑值不在预设列表时返回该原始值（用于下拉框兜底选项）。
func customValueIfUnknown(opts []Opt, value string) string {
	if value == "" {
		return ""
	}
	if inOptions(opts, value) {
		return ""
	}
	return value
}
