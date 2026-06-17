package ipwhitelistshaper_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

// postApproveWithOrigin is postApprove with an Origin header, for same-origin checks.
func postApproveWithOrigin(handler http.Handler, clientIP, form, origin string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "http://localhost/approve", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", origin)
	req.RemoteAddr = clientIP + ":1234"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}

// StubNotificationService records the most recent notification of each type
// behind a mutex (no channels/select, no pointers to imported types), so the
// suite is interpretable by yaegi while staying safe under the -race detector.
type StubNotificationService struct {
	mu         sync.Mutex
	knock      i.IPData
	approve    i.IPData
	hasKnock   bool
	hasApprove bool
}

func (s *StubNotificationService) SendKnockNotification(_ string, ipData i.IPData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.knock = ipData
	s.hasKnock = true
}

func (s *StubNotificationService) SendApproveConfirmNotification(ipData i.IPData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.approve = ipData
	s.hasApprove = true
}

// waitKnock polls for a knock notification (sent from a goroutine), consuming
// and returning it, or fails after ~1s.
func (s *StubNotificationService) waitKnock(t *testing.T) i.IPData {
	t.Helper()
	for n := 0; n < 100; n++ {
		s.mu.Lock()
		if s.hasKnock {
			v := s.knock
			s.hasKnock = false
			s.mu.Unlock()
			return v
		}
		s.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("knock notification was never sent")
	return i.IPData{}
}

// waitApprove is the approval-notification counterpart of waitKnock.
func (s *StubNotificationService) waitApprove(t *testing.T) i.IPData {
	t.Helper()
	for n := 0; n < 100; n++ {
		s.mu.Lock()
		if s.hasApprove {
			v := s.approve
			s.hasApprove = false
			s.mu.Unlock()
			return v
		}
		s.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("approve notification was never sent")
	return i.IPData{}
}

// knockSent reports whether a knock notification arrived within a short window,
// consuming it; used for negative assertions.
func (s *StubNotificationService) knockSent() bool {
	time.Sleep(100 * time.Millisecond)
	s.mu.Lock()
	defer s.mu.Unlock()
	had := s.hasKnock
	s.hasKnock = false
	return had
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
	notificationService := &StubNotificationService{}
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
