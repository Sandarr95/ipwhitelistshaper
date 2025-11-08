package ipwhitelistshaper

// Config defines the plugin configuration.
type Config struct {
	ExcludedIPs                []string `json:"excludedIPs,omitempty"`
	WhitelistedIPs             []string `json:"whitelistedIPs,omitempty"`
	IPStrategyDepth            int      `json:"ipStrategyDepth,omitempty"`
	DefaultPrivateClassSources bool     `json:"defaultPrivateClassSources,omitempty"`
	ExpirationTime             int      `json:"expirationTime,omitempty"` // Whitelist duration in seconds
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
		DefaultPrivateClassSources: true,
		ExpirationTime:             300, // Default 5 minutes whitelist duration
		SecretKey:                  generateRandomKey(),
		KnockEndpoint:              "/knock-knock",
		ApprovalURL:                "",

		// Default file storage configuration
		StorageEnabled: true,
		StoragePath:    "/plugins-storage/ipwhitelistshaper",
		storageReadOnly: false,
	}
}
