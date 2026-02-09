package ipwhitelistshaper_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	i "github.com/hhftechnology/ipwhitelistshaper"
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
	approveUri := fmt.Sprintf("/approve?%s", getApprovalQueryString(lastKnock))
	approveRec := testRequest(approveUri, handler, clientIP1) // Approve request coming from clientIP1
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
	approveUri := fmt.Sprintf("/approve?%s", getApprovalQueryString(lastKnock))
	testRequest(approveUri, handler, clientIP1)
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
