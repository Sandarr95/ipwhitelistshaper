package ipwhitelistshaper

import (
	"sync"
)

type IPWhitelistShaperRegistry struct {
	mutex sync.Mutex
	registry map[string]*IPWhitelistShaper
}

var (
	once sync.Once
	instance IPWhitelistShaperRegistry
)

func GetIPWhitelistShaperRegistryInstance() *IPWhitelistShaperRegistry {
	once.Do(func() {
		instance = IPWhitelistShaperRegistry{
			registry: make(map[string]*IPWhitelistShaper),
		}
	})
	return &instance
}

func RegisterIPWhitelistShaper(
    name string,
	config *Config,
	notificationService INotificationService,
	storageService IStorageService,
) (*IPWhitelistShaper, error) {
	instance := GetIPWhitelistShaperRegistryInstance()
	instance.mutex.Lock()
	defer instance.mutex.Unlock()
	_, exists := instance.registry[name]
	if !exists {
		ipwhitelistshaper, err := NewIPWhitelistShaper(name, config, notificationService, storageService)
		if err != nil {
			return nil, err
		}
		instance.registry[name] = ipwhitelistshaper
	}
	return instance.registry[name], nil
}
