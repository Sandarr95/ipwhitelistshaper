package ipwhitelistshaper_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"

	i "codeberg.org/Sandarr95/ipwhitelistshaper"
)

// postApprove submits a form-encoded approval POST (the new approval transport,
// where the token arrives via the page's URL fragment and is POSTed by JS).
func postApprove(handler http.Handler, clientIP, form string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "http://localhost/approve", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if strings.Contains(clientIP, ":") {
		req.RemoteAddr = fmt.Sprintf("[%s]:1234", clientIP)
	} else {
		req.RemoteAddr = fmt.Sprintf("%s:1234", clientIP)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}

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
	countStores atomic.Int64
	countLoads  atomic.Int64
}

func (s *StubStorageService) Store(whitelistedIPs map[string]i.IPData, pendingApprovals map[string]i.IPData) error {
	s.countStores.Add(1)
	return nil
}

func (s *StubStorageService) Load() (map[string]i.IPData, map[string]i.IPData, error) {
	s.countLoads.Add(1)
	return nil, nil, nil
}

func StubNew(ctx context.Context, next http.Handler, config *i.Config, name string) (http.Handler, *StubNotificationService, *StubStorageService, error) {
	_, cancel := context.WithCancel(ctx)
	notificationService := &StubNotificationService{
		knockCh:   make(chan i.IPData, 1),
		approveCh: make(chan i.IPData, 1),
	}
	storageService := &StubStorageService{}

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
