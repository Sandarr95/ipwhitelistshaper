package ipwhitelistshaper_test

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	i "github.com/hhftechnology/ipwhitelistshaper/src"
)

type StubNotificationService struct {
	lastKnock i.IPData
	lastApprove i.IPData
}

func (s *StubNotificationService) SendKnockNotification(approvalURLBase string, ipData i.IPData) {
	s.lastKnock = ipData
}

func (s *StubNotificationService) SendApproveConfirmNotification(ipData i.IPData) {
	s.lastApprove = ipData
}

func (s *StubNotificationService) getApprovalQueryString() string {
	params2 := url.Values{}
	params2.Add("token", s.lastKnock.ValidationID)
	params2.Add("validationCode", s.lastKnock.ValidationCode)
	params2.Add("ip", s.lastKnock.IP)
	params2.Add("expiration", strconv.Itoa(300))
	return params2.Encode()
}

type StubStorageService struct {
	countStores int
	countLoads int
}

func (s *StubStorageService) Store(whitelistedIPs map[string]i.IPData, pendingApprovals map[string]i.IPData) error {
	s.countStores += 1
	return nil
}

func (s *StubStorageService) Load() (map[string]i.IPData, map[string]i.IPData, error) {
	s.countLoads += 1
	return nil, nil, nil
}

func StubNew(ctx context.Context, next http.Handler, config *i.Config, name string) (http.Handler, *StubNotificationService, *StubStorageService, error) {
	_, cancel := context.WithCancel(ctx)
	notificationService := &StubNotificationService{}
	storageService := &StubStorageService{
		countStores: 0,
		countLoads: 0,
	}

	ipWhitelistShaper, err := i.RegisterIPWhitelistShaper(name, config, notificationService, storageService)
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}

	ipWhitelistShaperHandler, err := i.NewHandler(name, next, config, ipWhitelistShaper, cancel)
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}

	return ipWhitelistShaperHandler, notificationService, storageService, nil
}
