package ipwhitelistshaper

// Config defines the plugin configuration.
type Config struct {
	ExcludedIPs                []string `json:"excludedIPs,omitempty"`
	WhitelistedIPs             []string `json:"whitelistedIPs,omitempty"`
	IPStrategyDepth            int      `json:"ipStrategyDepth,omitempty"`
	IPv6PrefixLength           int      `json:"ipv6PrefixLength,omitempty"` // 0 or > 128 means exact match (default).
	DefaultPrivateClassSources bool     `json:"defaultPrivateClassSources,omitempty"`
	ExpirationTime             int      `json:"expirationTime,omitempty"` // Whitelist duration in seconds
	MaxPendingApprovals        int      `json:"maxPendingApprovals,omitempty"` // Cap on concurrent pending approvals (<=0 uses default)
	SecretKey                  string   `json:"secretKey,omitempty"`
	NotificationURL            string   `json:"notificationURL,omitempty"`
	NotificationURLFile        string   `json:"notificationURLFile,omitempty"`
	KnockEndpoint              string   `json:"knockEndpoint,omitempty"`
	ApprovalURL                string   `json:"approvalURL,omitempty"`

	// File storage configuration
	StorageEnabled bool   `json:"storageEnabled,omitempty"`
	StoragePath    string `json:"storagePath,omitempty"`

	// Internal flag (not exposed to config)
	storageReadOnly bool   // Flag to indicate read-only storage mode
}

// CreateConfig creates a default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		ExcludedIPs:                []string{},
		WhitelistedIPs:             []string{},
		IPStrategyDepth:            0,
		IPv6PrefixLength:           0,
		DefaultPrivateClassSources: true,
		ExpirationTime:             300, // Default 5 minutes whitelist duration
		MaxPendingApprovals:        1024,
		SecretKey:                  generateRandomKey(),
		KnockEndpoint:              "/knock-knock",
		ApprovalURL:                "",

		// Default file storage configuration
		StorageEnabled: true,
		StoragePath:    "/plugins-storage/ipwhitelistshaper",
		storageReadOnly: false,
	}
}
