package ipwhitelistshaper_test

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	i "github.com/hhftechnology/ipwhitelistshaper"
)

type StubNotificationService struct {
	knockCh chan i.IPData
	approveCh chan i.IPData
}

func (s *StubNotificationService) SendKnockNotification(approvalURLBase string, ipData i.IPData) {
	select {
	case s.knockCh <- ipData:
	default:
	}
}

func (s *StubNotificationService) SendApproveConfirmNotification(ipData i.IPData) {
	select {
	case s.approveCh <- ipData:
	default:
	}
}

func getApprovalQueryString(ipData i.IPData) string {
	params2 := url.Values{}
	params2.Add("token", ipData.ValidationID)
	params2.Add("validationCode", ipData.ValidationCode)
	params2.Add("ip", ipData.IP)
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
	notificationService := &StubNotificationService{
		knockCh:   make(chan i.IPData, 1),
		approveCh: make(chan i.IPData, 1),
	}
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
