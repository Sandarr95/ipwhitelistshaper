package ipwhitelistshaper

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"
)

func generateRandomKey() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	bytes := make([]byte, 32)
	_, err := r.Read(bytes)
	if err != nil { for i := range bytes { bytes[i] = byte(r.Intn(256)) } }
	return hex.EncodeToString(bytes)
}

func getClientIP(req *http.Request, depth int, excludedIPChecker *SourceRangeChecker) string {
	remoteIP, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil { remoteIP = req.RemoteAddr }
	if depth > 0 {
		xff := req.Header.Get("X-Forwarded-For")
		if xff != "" {
			ips := strings.Split(xff, ",")
			processedIPs := make([]string, 0, len(ips))
			for _, ipStr := range ips {
				trimmedIP := strings.TrimSpace(ipStr)
				if excludedIPChecker.Contains(trimmedIP) { continue; }
				processedIPs = append(processedIPs, trimmedIP)
			}
			if len(processedIPs) >= depth {
				targetIndex := len(processedIPs) - depth;
				return processedIPs[targetIndex]
			} else if len(processedIPs) > 0 {
				return processedIPs[0]
			}
		}
	}
	return remoteIP
}

func getScheme(req *http.Request) string {
	if req.TLS != nil { return "https" }
	if scheme := req.Header.Get("X-Forwarded-Proto"); scheme != "" { return scheme }
	if scheme := req.Header.Get("X-Scheme"); scheme != "" { return scheme }
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
