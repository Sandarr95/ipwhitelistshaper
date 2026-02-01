package ipwhitelistshaper

import (
	"context"
	"net/http"
)

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	pluginCtx, cancel := context.WithCancel(context.Background())
	notificationService := initNotificationService(name, config, pluginCtx)
	storageService := initStorageService(name, config)

	ipWhitelistShaper, err := RegisterIPWhitelistShaper(name, config, notificationService, storageService)
	if err != nil {
		cancel()
		return nil, err
	}

	ipWhitelistShaperHandler, err := NewHandler(name, next, config, ipWhitelistShaper, cancel)
	if err != nil {
		cancel()
		return nil, err
	}

	return ipWhitelistShaperHandler, nil
}
