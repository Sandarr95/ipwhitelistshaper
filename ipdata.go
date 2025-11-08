package ipwhitelistshaper

import (
	"fmt"
	"time"
)

// IPData stores information about whitelisted IPs or pending approvals
type IPData struct {
	IP              string    `json:"ip"`             // IP
	ExpiresAt       time.Time `json:"expiresAt"`      // Expiration time for whitelist entry OR pending request
	ValidationID    string    `json:"validationId"`   // Token associated with the request/entry
	ValidationCode  string    `json:"validationCode"` // User-facing code for verification
}

func isValid(mapOfIPs map[string]IPData, clientIP string) bool {
	ipData, exists := mapOfIPs[clientIP]
	return exists && time.Now().Before(ipData.ExpiresAt)
}

func getValid(mapOfIPs map[string]IPData, clientIP string) (*IPData, error) {
	if isValid(mapOfIPs, clientIP) {
		ipData := mapOfIPs[clientIP]
		return &ipData, nil
	}
	return nil, fmt.Errorf("clientIP not valid in map of IPData")
}
