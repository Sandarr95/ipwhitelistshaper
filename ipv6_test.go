package ipwhitelistshaper_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	i "codeberg.org/Sandarr95/ipwhitelistshaper"
)

func TestIPv6PrefixWhitelist(t *testing.T) {
	// Create a test configuration with IPv6 Prefix enabled
	config := i.CreateConfig()
	config.DefaultPrivateClassSources = false
	config.KnockEndpoint = "/knock-knock"
	config.IPv6PrefixLength = 64
	config.StorageEnabled = false

	// Mock client IPs
	clientIP1 := "2001:db8::1"
	clientIP2 := "2001:db8::2" // Same prefix /64
	clientIP3 := "2001:db8:1::1" // Different prefix

	// Create dummy next handler
	route := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusAccepted)
		rw.Write([]byte("Accepted"))
	})

	// Create the plugin handler
	handler, notification, _, err := StubNew(context.Background(), route, config, "ipwhitelistshaperIPv6")
	if err != nil {
		t.Fatalf("Error creating plugin handler: %v", err)
	}

	// Test 1: All IPs are initially forbidden
	for _, ip := range []string{clientIP1, clientIP2, clientIP3} {
		rec := testRequest("/", handler, ip)
		if rec.Code != http.StatusForbidden {
			t.Errorf("Expected status code %d for IP %s, got %d", http.StatusForbidden, ip, rec.Code)
		}
	}

	// Test 2: Knock from clientIP1
	knockRec := testRequest("/knock-knock", handler, clientIP1)
	if knockRec.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, knockRec.Code)
	}

	var lastKnock i.IPData
	select {
	case lastKnock = <-notification.knockCh:
	case <-time.After(time.Second):
		t.Fatal("Knock notification was never sent")
	}
	if lastKnock.IP != clientIP1 {
		t.Errorf("Expected last knock from IP: %q, got %q", clientIP1, lastKnock.IP)
	}

	// Test 3: Approve clientIP1
	approveRec := postApprove(handler, clientIP1, getApprovalQueryString(lastKnock)) // Approve request coming from clientIP1
	if approveRec.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, approveRec.Code)
	}

	// Wait for approve notification
	select {
	case <-notification.approveCh:
	case <-time.After(time.Second):
		t.Fatal("Approve notification was never sent")
	}

	// Test 4: clientIP1 is now allowed
	rec1 := testRequest("/", handler, clientIP1)
	if rec1.Code != http.StatusAccepted {
		t.Errorf("Expected status code %d for clientIP1, got %d", http.StatusAccepted, rec1.Code)
	}

	// Test 5: clientIP2 (same prefix) is ALSO allowed
	rec2 := testRequest("/", handler, clientIP2)
	if rec2.Code != http.StatusAccepted {
		t.Errorf("Expected status code %d for clientIP2 (same prefix), got %d", http.StatusAccepted, rec2.Code)
	}

	// Test 6: clientIP3 (different prefix) is still forbidden
	rec3 := testRequest("/", handler, clientIP3)
	if rec3.Code != http.StatusForbidden {
		t.Errorf("Expected status code %d for clientIP3 (diff prefix), got %d", http.StatusForbidden, rec3.Code)
	}
}

func TestIPv4WithIPv6Config(t *testing.T) {
	// Ensure IPv4 still works as exact match even if IPv6PrefixLength is set
	config := i.CreateConfig()
	config.IPv6PrefixLength = 64
	config.DefaultPrivateClassSources = false
	config.StorageEnabled = false
	config.KnockEndpoint = "/knock-knock"

	clientIP1 := "192.168.1.10"
	clientIP2 := "192.168.1.11" // Same /24 but should not matter as we don't do prefix for IPv4

	route := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusAccepted)
	})

	handler, notification, _, _ := StubNew(context.Background(), route, config, "ipwhitelistshaperIPv4")

	// Knock IP1
	testRequest("/knock-knock", handler, clientIP1)
	var lastKnock i.IPData
	select {
	case lastKnock = <-notification.knockCh:
	case <-time.After(time.Second):
		t.Fatal("Knock notification was never sent")
	}

	// Approve IP1
	postApprove(handler, clientIP1, getApprovalQueryString(lastKnock))
	select {
	case <-notification.approveCh:
	case <-time.After(time.Second):
		t.Fatal("Approve notification was never sent")
	}

	// IP1 Allowed
	if testRequest("/", handler, clientIP1).Code != http.StatusAccepted {
		t.Error("IP1 should be allowed")
	}

	// IP2 Forbidden (Exact match for IPv4)
	if testRequest("/", handler, clientIP2).Code != http.StatusForbidden {
		t.Error("IP2 should be forbidden (IPv4 exact match)")
	}
}

// With IPv6 prefix bucketing, a whole subnet shares a single pending approval:
// a second client in the same /64 joins the existing request (one validation
// code, no second notification) instead of creating its own.
func TestIPv6PrefixSharedPendingPerSubnet(t *testing.T) {
	config := i.CreateConfig()
	config.DefaultPrivateClassSources = false
	config.KnockEndpoint = "/knock-knock"
	config.IPv6PrefixLength = 64
	config.StorageEnabled = false

	clientIP1 := "2001:db8::1"
	clientIP2 := "2001:db8::2" // Same prefix /64

	route := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusAccepted)
	})

	handler, notification, _, _ := StubNew(context.Background(), route, config, "ipv6SharedPending")

	// 1. Client 1 knocks and triggers the only notification for this subnet.
	rec1 := testRequest("/knock-knock", handler, clientIP1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec1.Code)
	}
	var knock1 i.IPData
	select {
	case knock1 = <-notification.knockCh:
	case <-time.After(time.Second):
		t.Fatal("Knock 1 notification not received")
	}

	// 2. Client 2 (same /64) joins the existing pending request.
	rec2 := testRequest("/knock-knock", handler, clientIP2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec2.Code)
	}
	if !strings.Contains(rec2.Body.String(), "An approval request is already pending") {
		t.Errorf("Client 2 should share the subnet's pending approval")
	}
	if !strings.Contains(rec2.Body.String(), knock1.ValidationCode) {
		t.Errorf("Client 2 should see the same validation code %q", knock1.ValidationCode)
	}

	// No second notification should be sent for the same subnet.
	select {
	case extra := <-notification.knockCh:
		t.Errorf("Unexpected second notification for same subnet: %+v", extra)
	case <-time.After(100 * time.Millisecond):
	}

	// 3. Admin approves the subnet (via client 1).
	postApprove(handler, clientIP1, getApprovalQueryString(knock1))
	select {
	case <-notification.approveCh:
	case <-time.After(time.Second):
		t.Fatal("Approve notification not received")
	}

	// 4. Both clients in the subnet are now allowed.
	if testRequest("/", handler, clientIP1).Code != http.StatusAccepted {
		t.Error("Client 1 should be allowed")
	}
	if testRequest("/", handler, clientIP2).Code != http.StatusAccepted {
		t.Error("Client 2 should be allowed")
	}

	// 5. Re-approving the already-whitelisted subnet returns the success page.
	recApprove2 := postApprove(handler, clientIP2, getApprovalQueryString(knock1))
	if recApprove2.Code != http.StatusOK {
		t.Errorf("Expected 200 for already approved, got %d", recApprove2.Code)
	}
}
