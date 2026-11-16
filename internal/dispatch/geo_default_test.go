package dispatch

import (
	"net/http/httptest"
	"testing"
)

// 地域兜底回归：头优先 > default_country > ZZ
func TestDetectCountryFallback(t *testing.T) {
	defer SetDefaultCountry("")
	r := httptest.NewRequest("GET", "/", nil)
	if got := detectCountry(r); got != "ZZ" {
		t.Fatalf("unset default: want ZZ got %s", got)
	}
	SetDefaultCountry("cn")
	if got := detectCountry(r); got != "CN" {
		t.Fatalf("default=cn: want CN got %s", got)
	}
	r.Header.Set("CF-IPCountry", "us")
	if got := detectCountry(r); got != "US" {
		t.Fatalf("header priority: want US got %s", got)
	}
}
