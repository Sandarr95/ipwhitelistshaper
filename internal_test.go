package ipwhitelistshaper

import (
	"context"
	"crypto/tls"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGetClientIP(t *testing.T) {
	noExclusions, _ := NewSourceRangeChecker([]string{})
	excludeProxy, _ := NewSourceRangeChecker([]string{"2.2.2.2/32"})

	tests := []struct {
		name     string
		remote   string
		xff      string
		depth    int
		excluded *SourceRangeChecker
		want     string
	}{
		{"depth 0 strips port and ignores xff", "9.9.9.9:1234", "1.1.1.1, 3.3.3.3", 0, noExclusions, "9.9.9.9"},
		{"remote without port", "9.9.9.9", "", 0, noExclusions, "9.9.9.9"},
		{"depth 1 takes rightmost", "9.9.9.9:1234", "1.1.1.1, 3.3.3.3", 1, noExclusions, "3.3.3.3"},
		{"depth 2 walks left", "9.9.9.9:1234", "1.1.1.1, 3.3.3.3", 2, noExclusions, "1.1.1.1"},
		{"depth 2 of three", "9.9.9.9:1234", "1.1.1.1, 5.5.5.5, 3.3.3.3", 2, noExclusions, "5.5.5.5"},
		{"depth beyond chain fails closed", "9.9.9.9:1234", "1.1.1.1, 3.3.3.3", 5, noExclusions, ""},
		{"excluded entry skipped before depth", "9.9.9.9:1234", "1.1.1.1, 2.2.2.2, 3.3.3.3", 1, excludeProxy, "3.3.3.3"},
		{"excluded entry skipped, depth 2", "9.9.9.9:1234", "1.1.1.1, 2.2.2.2, 3.3.3.3", 2, excludeProxy, "1.1.1.1"},
		{"excluded leaves too few, fails closed", "9.9.9.9:1234", "1.1.1.1, 2.2.2.2", 2, excludeProxy, ""},
		{"depth set but no xff fails closed", "9.9.9.9:1234", "", 2, noExclusions, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/", nil)
			req.RemoteAddr = tt.remote
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if got := getClientIP(req, tt.depth, tt.excluded); got != tt.want {
				t.Errorf("getClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetScheme(t *testing.T) {
	tests := []struct {
		name    string
		useTLS  bool
		xfproto string
		xscheme string
		want    string
	}{
		{"tls connection is https", true, "", "", "https"},
		{"x-forwarded-proto https", false, "https", "", "https"},
		{"x-forwarded-proto http", false, "http", "", "http"},
		{"x-forwarded-proto is normalised", false, "HTTPS", "", "https"},
		{"invalid x-forwarded-proto is ignored", false, "javascript", "", "http"},
		{"x-scheme fallback", false, "", "https", "https"},
		{"default is http", false, "", "", "http"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/", nil)
			req.TLS = nil
			if tt.useTLS {
				req.TLS = &tls.ConnectionState{}
			}
			if tt.xfproto != "" {
				req.Header.Set("X-Forwarded-Proto", tt.xfproto)
			}
			if tt.xscheme != "" {
				req.Header.Set("X-Scheme", tt.xscheme)
			}
			if got := getScheme(req); got != tt.want {
				t.Errorf("getScheme() = %q, want %q", got, tt.want)
			}
		})
	}
}

func providerLabel(service INotificationService) string {
	switch service.(type) {
	case *DiscordNotificationService:
		return "discord"
	case *SlackNotificationService:
		return "slack"
	case *TelegramNotificationService:
		return "telegram"
	case *GenericNotificationService:
		return "generic"
	case *StandardOutNotificationService:
		return "stdout"
	default:
		return "unknown"
	}
}

func TestInitNotificationServiceProviderSelection(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://discord.com/api/webhooks/123/abc", "discord"},
		{"https://hooks.slack.com/services/T0/B0/xyz", "slack"},
		{"https://api.telegram.org/bot123:ABC/sendMessage", "telegram"},
		{"https://notify.example.com/webhook", "generic"},
		{"", "stdout"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			config := CreateConfig()
			config.NotificationURL = tt.url
			service := initNotificationService("provider-test", config, context.Background())
			if got := providerLabel(service); got != tt.want {
				t.Errorf("initNotificationService(%q) selected %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestEvictExpiredLocked(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	future := time.Now().Add(time.Minute)
	shaper := &IPWhitelistShaper{
		whitelistedIPs: map[string]IPData{
			"keep-wl":   {IP: "keep-wl", ExpiresAt: future},
			"expire-wl": {IP: "expire-wl", ExpiresAt: past},
		},
		pendingApprovals: map[string]IPData{
			"keep-pend":   {IP: "keep-pend", ExpiresAt: future},
			"expire-pend": {IP: "expire-pend", ExpiresAt: past},
		},
	}

	shaper.evictExpiredLocked()

	if _, ok := shaper.whitelistedIPs["expire-wl"]; ok {
		t.Error("expired whitelist entry should be evicted")
	}
	if _, ok := shaper.whitelistedIPs["keep-wl"]; !ok {
		t.Error("valid whitelist entry should be kept")
	}
	if _, ok := shaper.pendingApprovals["expire-pend"]; ok {
		t.Error("expired pending entry should be evicted")
	}
	if _, ok := shaper.pendingApprovals["keep-pend"]; !ok {
		t.Error("valid pending entry should be kept")
	}
}

func TestFileStorageRoundTrip(t *testing.T) {
	service := FileStorageService{name: "roundtrip", storagePath: t.TempDir()}
	expires := time.Now().Add(time.Hour)
	whitelisted := map[string]IPData{
		"1.2.3.4": {IP: "1.2.3.4", ExpiresAt: expires, ValidationID: "tok-wl", ValidationCode: "apple"},
	}
	pending := map[string]IPData{
		"5.6.7.8": {IP: "5.6.7.8", ExpiresAt: expires, ValidationID: "tok-pend", ValidationCode: "banana"},
	}

	if err := service.Store(whitelisted, pending); err != nil {
		t.Fatalf("Store: %v", err)
	}

	gotWhitelisted, gotPending, err := service.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got := gotWhitelisted["1.2.3.4"]; got.ValidationID != "tok-wl" || got.ValidationCode != "apple" || !got.ExpiresAt.Equal(expires) {
		t.Errorf("whitelist round-trip mismatch: %+v", got)
	}
	if got := gotPending["5.6.7.8"]; got.ValidationID != "tok-pend" || got.ValidationCode != "banana" || !got.ExpiresAt.Equal(expires) {
		t.Errorf("pending round-trip mismatch: %+v", got)
	}
}

func TestFileStoragePermissions(t *testing.T) {
	dir := t.TempDir()
	service := FileStorageService{name: "perms", storagePath: dir}
	if err := service.Store(map[string]IPData{}, map[string]IPData{}); err != nil {
		t.Fatalf("Store: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("state file permissions = %o, want 600 (tokens must not be world-readable)", perm)
	}
}

func TestFileStorageCorruptRecovery(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte("{ this is not valid json"), 0600); err != nil {
		t.Fatal(err)
	}

	service := FileStorageService{name: "corrupt", storagePath: dir}
	whitelisted, pending, err := service.Load()
	if err != nil {
		t.Fatalf("Load should recover from a corrupt file without error, got: %v", err)
	}
	if whitelisted == nil || pending == nil {
		t.Fatal("expected non-nil empty maps after corrupt-file recovery")
	}
	if len(whitelisted) != 0 || len(pending) != 0 {
		t.Errorf("expected empty maps after corrupt recovery, got %d/%d", len(whitelisted), len(pending))
	}
}
