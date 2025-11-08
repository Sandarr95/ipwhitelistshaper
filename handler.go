// filename: ipwhitelistshaper.go
// Package ipwhitelistshaper provides a Traefik middleware for dynamic IP whitelist management
package ipwhitelistshaper

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// IPWhitelistShaper implements the middleware functionality
type IPWhitelistShaperHandler struct {
	next               http.Handler
	cancel             context.CancelFunc
	config             *Config
	whitelistChecker   *SourceRangeChecker
	excludedChecker    *SourceRangeChecker
	ipWhitelistShaper  *IPWhitelistShaper
}

func NewHandler(name string, next http.Handler, config *Config, ipWhitelistShaper *IPWhitelistShaper, cancel context.CancelFunc) (http.Handler, error) {
	// Initialize the source ranges
	sourceRanges := []string{"127.0.0.1/32"} // Always allow localhost
	if config.DefaultPrivateClassSources {
		sourceRanges = append(sourceRanges, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
	}
	sourceRanges = append(sourceRanges, config.WhitelistedIPs...)

	whitelistChecker, err := NewSourceRangeChecker(sourceRanges)
	if err != nil {
		return nil, fmt.Errorf("error parsing whitelisted source ranges: %v", err)
	}

	excludedChecker, err := NewSourceRangeChecker(config.ExcludedIPs)
	if err != nil {
		return nil, fmt.Errorf("error parsing excluded source ranges: %v", err)
	}

	return &IPWhitelistShaperHandler {
	    next: next,
		config: config,
		cancel: cancel,
		whitelistChecker: whitelistChecker,
		excludedChecker: excludedChecker,
		ipWhitelistShaper: ipWhitelistShaper,
	}, nil
}

// ServeHTTP implements the http.Handler interface for the middleware
func (handler *IPWhitelistShaperHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	clientIP := getClientIP(req, handler.config.IPStrategyDepth, handler.excludedChecker)
	if clientIP == "" {
		http.Error(rw, "Could not determine client IP", http.StatusInternalServerError)
		return
	}

	// Handle special endpoints first
	if req.URL.Path == handler.config.KnockEndpoint {
		handler.ipWhitelistShaper.handleKnockRequest(rw, req, clientIP)
		return
	}
	if strings.HasPrefix(req.URL.Path, "/approve") {
		handler.ipWhitelistShaper.handleApproveRequest(rw, req)
		return
	}

	// --- Regular Request Flow ---
	if handler.whitelistChecker.Contains(clientIP) {
		handler.next.ServeHTTP(rw, req)
		return
	}

	if handler.ipWhitelistShaper.isWhitelisted(clientIP) {
		handler.next.ServeHTTP(rw, req)
		return
	}

	rw.WriteHeader(http.StatusForbidden)
	rw.Write([]byte("403 Forbidden"))
}

func (i *IPWhitelistShaperHandler) Close() error {
	i.cancel()
	err := i.ipWhitelistShaper.saveState()
	if err != nil {
		fmt.Printf("[%s] WARNING: Could not save final state on close: %v\n", i.ipWhitelistShaper.name, err)
	} else {
		fmt.Printf("[%s] INFO Final state saved successfully.\n", i.ipWhitelistShaper.name)
	}
	return nil
}
