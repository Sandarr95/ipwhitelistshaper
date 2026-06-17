package ipwhitelistshaper

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

func generateRandomKey() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		// crypto/rand only fails when the OS has no usable entropy source.
		// Failing closed is safer than handing out a predictable secret key.
		panic(fmt.Sprintf("ipwhitelistshaper: could not read from crypto/rand: %v", err))
	}
	return hex.EncodeToString(bytes)
}

func getClientIP(req *http.Request, depth int, excludedIPChecker *SourceRangeChecker) string {
	remoteIP, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil { remoteIP = req.RemoteAddr }
	if depth <= 0 {
		return remoteIP
	}
	// depth > 0: a trusted proxy chain is expected. Derive the client IP from
	// X-Forwarded-For and fail closed (return "") when the chain is shorter than
	// depth, matching Traefik's IPStrategy rather than trusting a spoofable entry.
	xff := req.Header.Get("X-Forwarded-For")
	if xff == "" {
		return ""
	}
	processedIPs := make([]string, 0)
	for _, ipStr := range strings.Split(xff, ",") {
		trimmedIP := strings.TrimSpace(ipStr)
		if excludedIPChecker.Contains(trimmedIP) { continue }
		processedIPs = append(processedIPs, trimmedIP)
	}
	if len(processedIPs) < depth {
		return ""
	}
	return processedIPs[len(processedIPs)-depth]
}

func getScheme(req *http.Request) string {
	if req.TLS != nil { return "https" }
	// Only accept validated scheme values; these headers are attacker-controllable.
	for _, header := range []string{"X-Forwarded-Proto", "X-Scheme"} {
		switch strings.ToLower(strings.TrimSpace(req.Header.Get(header))) {
		case "https": return "https"
		case "http": return "http"
		}
	}
	return "http"
}

// Helper function for debug logging
func maskDebugData(data map[string]IPData) map[string]string {
	result := make(map[string]string)
	count := 0
	for k, v := range data {
		if count < 3 { // Only show up to 3 sample entries
			result[k] = fmt.Sprintf("ValidID: %s..., ValidCode: %s, Expires: %s",
				truncateString(v.ValidationID, 8),
				v.ValidationCode,
				v.ExpiresAt.Format(time.RFC3339))
			count++
		}
	}
	return result
}

// Helper function to truncate strings for logging
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// Helper function to get map keys for debugging
func getMapKeys(m map[string]IPData) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
