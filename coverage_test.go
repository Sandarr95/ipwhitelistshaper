package ipwhitelistshaper_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	i "codeberg.org/Sandarr95/ipwhitelistshaper"
)

func acceptingRoute() http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusAccepted)
		rw.Write([]byte("Accepted"))
	})
}

// knockAndApprove drives a full knock + approve cycle for clientIP and waits
// for both notifications, failing the test if either never arrives.
func knockAndApprove(t *testing.T, handler http.Handler, notif *StubNotificationService, clientIP string) {
	t.Helper()
	if rec := testRequest("/knock-knock", handler, clientIP); rec.Code != http.StatusOK {
		t.Fatalf("knock: expected 200, got %d", rec.Code)
	}

	knock := notif.waitKnock(t)

	if rec := postApprove(handler, clientIP, getApprovalQueryString(knock)); rec.Code != http.StatusOK {
		t.Fatalf("approve: expected 200, got %d", rec.Code)
	}
	notif.waitApprove(t)
}

func TestWhitelistExpiration(t *testing.T) {
	config := i.CreateConfig()
	config.DefaultPrivateClassSources = false
	config.StorageEnabled = false
	config.KnockEndpoint = "/knock-knock"
	config.ExpirationTime = 1

	clientIP := "203.0.113.10"
	handler, notif, _, err := StubNew(context.Background(), acceptingRoute(), config, "expirationTest")
	if err != nil {
		t.Fatalf("Error creating plugin handler: %v", err)
	}

	knockAndApprove(t, handler, notif, clientIP)

	if rec := testRequest("/", handler, clientIP); rec.Code != http.StatusAccepted {
		t.Fatalf("Expected access granted right after approval, got %d", rec.Code)
	}

	time.Sleep(1100 * time.Millisecond)

	if rec := testRequest("/", handler, clientIP); rec.Code != http.StatusForbidden {
		t.Errorf("Expected access denied after expiration, got %d", rec.Code)
	}
}

func TestApproveRejectsWrongValidationCode(t *testing.T) {
	config := i.CreateConfig()
	config.DefaultPrivateClassSources = false
	config.StorageEnabled = false
	config.KnockEndpoint = "/knock-knock"

	clientIP := "203.0.113.20"
	handler, notif, _, err := StubNew(context.Background(), acceptingRoute(), config, "wrongCodeTest")
	if err != nil {
		t.Fatalf("Error creating plugin handler: %v", err)
	}

	testRequest("/knock-knock", handler, clientIP)
	knock := notif.waitKnock(t)

	params := url.Values{}
	params.Add("ip", knock.IP)
	params.Add("token", knock.ValidationID) // correct token
	params.Add("validationCode", "definitelywrong")
	if rec := postApprove(handler, clientIP, params.Encode()); rec.Code != http.StatusForbidden {
		t.Errorf("Expected 403 for wrong validation code, got %d", rec.Code)
	}

	if rec := testRequest("/", handler, clientIP); rec.Code != http.StatusForbidden {
		t.Errorf("Expected access to remain denied after failed approval, got %d", rec.Code)
	}
}

// A GET to /approve must only serve the page (where JS reads the fragment) and
// never approve — this is what stops link-unfurl/prefetch bots from approving.
func TestApproveGetDoesNotApprove(t *testing.T) {
	config := i.CreateConfig()
	config.DefaultPrivateClassSources = false
	config.StorageEnabled = false
	config.KnockEndpoint = "/knock-knock"

	clientIP := "203.0.113.50"
	handler, notif, _, err := StubNew(context.Background(), acceptingRoute(), config, "approveGet")
	if err != nil {
		t.Fatalf("Error creating plugin handler: %v", err)
	}

	testRequest("/knock-knock", handler, clientIP)
	knock := notif.waitKnock(t)

	// Even with valid params in the query, a GET serves the page and approves nothing.
	getRec := testRequest("/approve?"+getApprovalQueryString(knock), handler, clientIP)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET /approve: expected 200 page, got %d", getRec.Code)
	}
	if ct := getRec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("GET /approve: expected html page, got content-type %q", ct)
	}
	if rec := testRequest("/", handler, clientIP); rec.Code != http.StatusForbidden {
		t.Errorf("GET /approve must not whitelist; expected 403, got %d", rec.Code)
	}
}

func TestApproveRejectsCrossOriginPost(t *testing.T) {
	config := i.CreateConfig()
	config.DefaultPrivateClassSources = false
	config.StorageEnabled = false
	config.KnockEndpoint = "/knock-knock"

	clientIP := "203.0.113.51"
	handler, notif, _, err := StubNew(context.Background(), acceptingRoute(), config, "approveOrigin")
	if err != nil {
		t.Fatalf("Error creating plugin handler: %v", err)
	}

	testRequest("/knock-knock", handler, clientIP)
	knock := notif.waitKnock(t)

	form := getApprovalQueryString(knock)

	// Cross-origin POST is rejected and approves nothing.
	if rec := postApproveWithOrigin(handler, clientIP, form, "https://evil.example.com"); rec.Code != http.StatusForbidden {
		t.Errorf("cross-origin POST: expected 403, got %d", rec.Code)
	}
	if rec := testRequest("/", handler, clientIP); rec.Code != http.StatusForbidden {
		t.Errorf("cross-origin POST must not whitelist; got %d", rec.Code)
	}

	// Same-origin POST (Origin host matches request host) still approves.
	if rec := postApproveWithOrigin(handler, clientIP, form, "http://localhost"); rec.Code != http.StatusOK {
		t.Errorf("same-origin POST: expected 200, got %d", rec.Code)
	}
}

// probeApprove POSTs an approval with a deliberately invalid token and returns
// the response status and body (kept a package function rather than a closure
// so the suite stays interpretable by yaegi).
func probeApprove(handler http.Handler, ip string) (int, string) {
	params := url.Values{}
	params.Add("ip", ip)
	params.Add("token", "garbage-token")
	params.Add("validationCode", "garbage-code")
	rec := postApprove(handler, ip, params.Encode())
	return rec.Code, rec.Body.String()
}

// TestApproveDoesNotLeakState: probing /approve with an invalid token must
// return an identical response whether the IP is whitelisted, pending, or
// unknown — otherwise the endpoint is an oracle for an IP's state.
func TestApproveDoesNotLeakState(t *testing.T) {
	config := i.CreateConfig()
	config.DefaultPrivateClassSources = false
	config.StorageEnabled = false
	config.KnockEndpoint = "/knock-knock"

	handler, notif, _, err := StubNew(context.Background(), acceptingRoute(), config, "approveLeak")
	if err != nil {
		t.Fatalf("Error creating plugin handler: %v", err)
	}

	whitelistedIP := "203.0.113.61"
	knockAndApprove(t, handler, notif, whitelistedIP)

	pendingIP := "203.0.113.62"
	testRequest("/knock-knock", handler, pendingIP)
	notif.waitKnock(t)

	unknownIP := "203.0.113.63"

	codeW, bodyW := probeApprove(handler, whitelistedIP)
	codeP, bodyP := probeApprove(handler, pendingIP)
	codeU, bodyU := probeApprove(handler, unknownIP)

	if codeW != codeP || codeP != codeU {
		t.Errorf("status codes leak state: whitelisted=%d pending=%d unknown=%d", codeW, codeP, codeU)
	}
	if bodyW != bodyP || bodyP != bodyU {
		t.Errorf("response bodies leak state:\n whitelisted=%q\n pending=%q\n unknown=%q", bodyW, bodyP, bodyU)
	}
	if codeW != http.StatusForbidden {
		t.Errorf("expected 403 for an invalid approval attempt, got %d", codeW)
	}
}

func TestApproveIgnoresClientSuppliedExpiration(t *testing.T) {
	config := i.CreateConfig()
	config.DefaultPrivateClassSources = false
	config.StorageEnabled = false
	config.KnockEndpoint = "/knock-knock"
	config.ExpirationTime = 300

	clientIP := "203.0.113.30"
	handler, notif, _, err := StubNew(context.Background(), acceptingRoute(), config, "ignoreExpirationTest")
	if err != nil {
		t.Fatalf("Error creating plugin handler: %v", err)
	}

	testRequest("/knock-knock", handler, clientIP)
	knock := notif.waitKnock(t)

	params := url.Values{}
	params.Add("ip", knock.IP)
	params.Add("token", knock.ValidationID)
	params.Add("validationCode", knock.ValidationCode)
	params.Add("expiration", "999999") // attacker-supplied, must be ignored

	rec := postApprove(handler, clientIP, params.Encode())
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 on approval, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"expiresIn":300`) {
		t.Errorf("Expected server-configured expiration (300s) in response, body: %s", body)
	}
	if strings.Contains(body, "999999") {
		t.Errorf("Client-supplied expiration leaked into the approval")
	}
}

func TestDefaultPrivateClassSources(t *testing.T) {
	privateIP := "10.1.2.3"

	enabled := i.CreateConfig()
	enabled.DefaultPrivateClassSources = true
	enabled.StorageEnabled = false
	handlerEnabled, _, _, err := StubNew(context.Background(), acceptingRoute(), enabled, "privateEnabled")
	if err != nil {
		t.Fatalf("Error creating plugin handler: %v", err)
	}
	if rec := testRequest("/", handlerEnabled, privateIP); rec.Code != http.StatusAccepted {
		t.Errorf("Expected private IP allowed when defaultPrivateClassSources=true, got %d", rec.Code)
	}

	disabled := i.CreateConfig()
	disabled.DefaultPrivateClassSources = false
	disabled.StorageEnabled = false
	handlerDisabled, _, _, err := StubNew(context.Background(), acceptingRoute(), disabled, "privateDisabled")
	if err != nil {
		t.Fatalf("Error creating plugin handler: %v", err)
	}
	if rec := testRequest("/", handlerDisabled, privateIP); rec.Code != http.StatusForbidden {
		t.Errorf("Expected private IP denied when defaultPrivateClassSources=false, got %d", rec.Code)
	}
}

func TestPendingApprovalsCap(t *testing.T) {
	config := i.CreateConfig()
	config.DefaultPrivateClassSources = false
	config.StorageEnabled = false
	config.KnockEndpoint = "/knock-knock"
	config.MaxPendingApprovals = 2

	handler, _, _, err := StubNew(context.Background(), acceptingRoute(), config, "pendingCap")
	if err != nil {
		t.Fatalf("Error creating plugin handler: %v", err)
	}

	if rec := testRequest("/knock-knock", handler, "203.0.113.41"); rec.Code != http.StatusOK {
		t.Fatalf("first knock: expected 200, got %d", rec.Code)
	}
	if rec := testRequest("/knock-knock", handler, "203.0.113.42"); rec.Code != http.StatusOK {
		t.Fatalf("second knock: expected 200, got %d", rec.Code)
	}
	// Third distinct source exceeds the cap and is rejected.
	if rec := testRequest("/knock-knock", handler, "203.0.113.43"); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("third knock: expected 503 (cap reached), got %d", rec.Code)
	}
	// An already-pending source is still served (it is not a new entry).
	if rec := testRequest("/knock-knock", handler, "203.0.113.41"); rec.Code != http.StatusOK {
		t.Errorf("re-knock of pending source: expected 200, got %d", rec.Code)
	}
}

// TestConcurrentAccess hammers a single shared shaper from many goroutines to
// surface data races on its maps under the race detector.
func TestConcurrentAccess(t *testing.T) {
	config := i.CreateConfig()
	config.DefaultPrivateClassSources = false
	config.StorageEnabled = false
	config.KnockEndpoint = "/knock-knock"

	handler, notif, _, err := StubNew(context.Background(), acceptingRoute(), config, "concurrentAccess")
	if err != nil {
		t.Fatalf("Error creating plugin handler: %v", err)
	}

	approvedIP := "198.51.100.1"
	knockAndApprove(t, handler, notif, approvedIP)

	var wg sync.WaitGroup
	for n := 0; n < 50; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			ip := fmt.Sprintf("203.0.113.%d", n+1)
			testRequest("/", handler, ip)          // read path (denied)
			testRequest("/knock-knock", handler, ip) // write path
			testRequest("/", handler, approvedIP)    // read path (allowed)
		}(n)
	}
	wg.Wait()

	if rec := testRequest("/", handler, approvedIP); rec.Code != http.StatusAccepted {
		t.Errorf("Approved IP should remain allowed after concurrent load, got %d", rec.Code)
	}
}
