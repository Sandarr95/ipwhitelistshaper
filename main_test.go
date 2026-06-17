package ipwhitelistshaper_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	i "github.com/hhftechnology/ipwhitelistshaper"
)

func testRequest(uri string, handler http.Handler, clientIP string) *httptest.ResponseRecorder {
	url := fmt.Sprintf("http://localhost%s", uri)
	request := httptest.NewRequest(http.MethodGet, url, nil)
	if strings.Contains(clientIP, ":") {
		request.RemoteAddr = fmt.Sprintf("[%s]:1234", clientIP)
	} else {
		request.RemoteAddr = fmt.Sprintf("%s:1234", clientIP)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestIPWhitelistShaperHandler(t *testing.T) {
	// Create a test configuration
	config := i.CreateConfig()
	config.DefaultPrivateClassSources = false
	config.KnockEndpoint = "/knock-knock"
	config.WhitelistedIPs = []string{"192.168.1.1/32"}
	config.StorageEnabled = false

	// Mock client IP
	clientIP := "192.168.100.1"

	// Create dummy next handlers
	routeA_1 := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusAccepted)
		rw.Write([]byte("Accepted"))
	})
	routeA_2 := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusNoContent)
		rw.Write([]byte("OK"))
	})
	routeB := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusNoContent)
		rw.Write([]byte(""))
	})

	// Create the plugin handler
	handlerA_1, notificationA_1, storageA_1, err := StubNew(context.Background(), routeA_1, config, "ipwhitelistshaperA")
	if err != nil {
		t.Fatalf("Error creating plugin handler: %v", err)
	}
	handlerA_2, _, _, err := StubNew(context.Background(), routeA_2, config, "ipwhitelistshaperA")
	if err != nil {
		t.Fatalf("Error creating plugin handler: %v", err)
	}
	handlerB, _, _, err := StubNew(context.Background(), routeB, config, "ipwhitelistshaperB")
	if err != nil {
		t.Fatalf("Error creating plugin handler: %v", err)
	}

	// Test 1: All routes are forbidden
	for _, handler := range []http.Handler{ handlerA_1, handlerA_2, handlerB } {
		rec := testRequest("/", handler, clientIP)
		if rec.Code != http.StatusForbidden {
			t.Errorf("Expected status code %d, got %d", http.StatusForbidden, rec.Code)
		}
	}

	// Test 2: Knock succeeds on routeA_1
	knockRec := testRequest("/knock-knock", handlerA_1, clientIP)
	if knockRec.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, knockRec.Code)
	}
	if knockRec.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Errorf("Expected Content-Type %q, got %q", "text/html; charset=utf-8", knockRec.Header().Get("Content-Type"))
	}
	var lastKnock i.IPData
	select {
	case lastKnock = <-notificationA_1.knockCh:
	case <-time.After(time.Second):
		t.Fatal("Knock notification was never sent")
	}
	if lastKnock.IP != clientIP {
		t.Errorf("Expected last knock from IP: %q, got %q", clientIP, lastKnock.IP)
	}

	// Test 3: Trying approve with wrong token fails
	wrongUrlParams := url.Values{}
	wrongUrlParams.Add("validationCode", lastKnock.ValidationCode)
	wrongUrlParams.Add("ip", lastKnock.IP)
	wrongUrlParams.Add("token", "invalid")
	wrongApproveRec := postApprove(handlerA_1, clientIP, wrongUrlParams.Encode())
	if wrongApproveRec.Code != http.StatusForbidden {
		t.Errorf("Expected status code %d, got %d", http.StatusForbidden, wrongApproveRec.Code)
	}

	// Test 4: Before approving, requests are still denied
	beforeApprovalRec := testRequest("/", handlerA_1, clientIP)
	if beforeApprovalRec.Code != http.StatusForbidden {
		t.Errorf("Expected clientIP (%q) not to be whitelisted yet", clientIP)
	}

	// Test 5: Approval with correct parameters succeeds
	approveRec := postApprove(handlerA_1, clientIP, getApprovalQueryString(lastKnock))
	if approveRec.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, approveRec.Code)
	}

	var lastApprove i.IPData
	select {
	case lastApprove = <-notificationA_1.approveCh:
	case <-time.After(time.Second):
		t.Fatal("Approve notification was never sent")
	}
	if lastApprove.IP != clientIP {
		t.Errorf("Expected last approve for IP: %q, got %q", clientIP, lastApprove.IP)
	}

	// Test 6: Normal requests are now allowed on handlerA_1
	afterApprovalRec := testRequest("/", handlerA_1, clientIP)
	if afterApprovalRec.Code != http.StatusAccepted {
		t.Errorf("Expected status code %d, got %d", http.StatusAccepted, afterApprovalRec.Code)
	}

	// Test 7: Normal requests are still forbidden on handlerB
	stillForbiddenOnRouteBRec := testRequest("/", handlerB, clientIP)
	if stillForbiddenOnRouteBRec.Code != http.StatusForbidden {
		t.Errorf("Expected status code %d, got %d", http.StatusForbidden, stillForbiddenOnRouteBRec.Code)
	}

	// Test 8: Normal requests are also allowed on handlerA_2, as it uses the same config
	approvalOnRouteA_2Rec := testRequest("/", handlerA_2, clientIP)
	if approvalOnRouteA_2Rec.Code != http.StatusNoContent {
		t.Errorf("Expected status code %d, got %d", http.StatusNoContent, approvalOnRouteA_2Rec.Code)
	}

	// Test 9: Storage loads and stores happened
	if storageA_1.countLoads.Load() != 3 {
		t.Errorf("Expected %d loads, got %d", 3, storageA_1.countLoads.Load())
	}
	if storageA_1.countStores.Load() != 2 {
		t.Errorf("Expected %d stores, got %d", 2, storageA_1.countStores.Load())
	}
}
