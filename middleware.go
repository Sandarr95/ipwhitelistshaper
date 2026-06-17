package ipwhitelistshaper

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

const defaultMaxPendingApprovals = 1024

type IPWhitelistShaper struct {
	name                string
	config              *Config
	storageService      IStorageService
	notificationService INotificationService
	whitelistedIPs      map[string]IPData // Map IP -> Whitelist Data
	pendingApprovals    map[string]IPData // Map IP -> Pending Approval Data
	mutex               sync.RWMutex // Protects maps: whitelistedIPs, pendingApprovals, lastRequestedIP
	wordList            []string
}

func NewIPWhitelistShaper(
	name string,
	config *Config,
	notificationService INotificationService,
	storageService IStorageService,
) (*IPWhitelistShaper, error) {
	if config.ExpirationTime <= 0 {
		config.ExpirationTime = 300 // Default if invalid
	}
	if config.MaxPendingApprovals <= 0 {
		config.MaxPendingApprovals = defaultMaxPendingApprovals
	}

	wordList := []string{
		"apple", "banana", "cherry", "dog", "elephant", "frog", "giraffe", "house",
		"igloo", "jacket", "kangaroo", "lemon", "monkey", "notebook", "orange", "penguin",
		"queen", "rainbow", "strawberry", "tiger", "umbrella", "violin", "watermelon",
		"xylophone", "yellow", "zebra", "airplane", "beach", "computer", "dolphin",
	}

	ipwhitelistshaper := &IPWhitelistShaper{
		name:                name,
		config:              config,
		storageService:      storageService,
		notificationService: notificationService,
		whitelistedIPs:      make(map[string]IPData),
		pendingApprovals:    make(map[string]IPData),
		wordList:            wordList,
	}
	ipwhitelistshaper.loadState()

	logStartupWarnings(name, config)

	return ipwhitelistshaper, nil
}

// logStartupWarnings surfaces operational risks once per plugin instance.
func logStartupWarnings(name string, config *Config) {
	fmt.Printf("[%s] WARNING: verbose DEBUG logging is enabled and includes approval tokens; filter or disable these logs and do not rely on them in production.\n", name)
	if config.ApprovalURL == "" {
		fmt.Printf("[%s] WARNING: approvalURL is not set; approval links fall back to the request Host header, which can be spoofed to leak the approval token. Set approvalURL explicitly in production.\n", name)
	}
	if config.IPStrategyDepth < 0 {
		fmt.Printf("[%s] WARNING: ipStrategyDepth is negative (%d); it is treated as 0 and X-Forwarded-For is ignored.\n", name, config.IPStrategyDepth)
	}
	if len(config.ExcludedIPs) > 0 && config.IPStrategyDepth <= 0 {
		fmt.Printf("[%s] WARNING: excludedIPs is configured but ipStrategyDepth is %d; excludedIPs only applies when ipStrategyDepth > 0 and will be ignored.\n", name, config.IPStrategyDepth)
	}
	if config.IPStrategyDepth > 0 {
		fmt.Printf("[%s] INFO ipStrategyDepth is %d; requests whose X-Forwarded-For has fewer than %d (non-excluded) entries are denied. Ensure this matches your trusted proxy count.\n", name, config.IPStrategyDepth, config.IPStrategyDepth)
	}
}

func (i *IPWhitelistShaper) getIPKey(ipStr string) string {
	if i.config.IPv6PrefixLength <= 0 || i.config.IPv6PrefixLength >= 128 {
		return ipStr
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ipStr
	}
	if ip.To4() != nil {
		return ipStr
	}

	mask := net.CIDRMask(i.config.IPv6PrefixLength, 128)
	maskedIP := ip.Mask(mask)
	return maskedIP.String()
}

func (i *IPWhitelistShaper) isWhitelisted(clientIP string) bool {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return isValid(i.whitelistedIPs, i.getIPKey(clientIP))
}

// handleKnockRequest processes requests to the knock-knock endpoint
func (i *IPWhitelistShaper) handleKnockRequest(rw http.ResponseWriter, req *http.Request, clientIP string) {
	key := i.getIPKey(clientIP)
	i.mutex.Lock()

	i.evictExpiredLocked()

	if isValid(i.whitelistedIPs, key) {
		i.mutex.Unlock()
		http.Redirect(rw, req, "/", http.StatusFound)
		return
	}

	// Pending approvals are bucketed by the same key we whitelist (the IPv6
	// prefix when configured), so a single subnet maps to one pending request.
	if pendingIpData, _ := getValid(i.pendingApprovals, key); pendingIpData != nil {
		validationCode := pendingIpData.ValidationCode
		i.mutex.Unlock()
		if err := i.saveState(); err != nil {
			fmt.Printf("[%s] WARNING: Could not save state during knock re-request: %v\n", i.name, err)
		}
		i.serveKnockPage(rw, validationCode, "An approval request is already pending. Please use the validation code below.")
		return
	}

	if len(i.pendingApprovals) >= i.config.MaxPendingApprovals {
		i.mutex.Unlock()
		fmt.Printf("[%s] WARNING: pending approvals cap (%d) reached; rejecting knock from %s\n", i.name, i.config.MaxPendingApprovals, clientIP)
		http.Error(rw, "Too many pending approval requests, please try again later", http.StatusServiceUnavailable)
		return
	}

	ipData := IPData{
		IP:             clientIP,
		ExpiresAt:      time.Now().Add(1 * time.Hour),
		ValidationID:   i.generateToken(clientIP),
		ValidationCode: i.getRandomUnusedWord(),
	}
	i.pendingApprovals[key] = ipData

	i.mutex.Unlock() // Unlock before synchronous save

	if err := i.saveState(); err != nil { // Synchronous save
		fmt.Printf("[%s] WARNING: Could not save state after creating pending approval: %v\n", i.name, err)
	} else {
		fmt.Printf("[%s] INFO State saved synchronously for pending approval IP: %s\n", i.name, clientIP)
	}

	approvalURLBase := i.config.ApprovalURL
	if approvalURLBase == "" {
		approvalURLBase = fmt.Sprintf("%s://%s", getScheme(req), req.Host)
	}
	go i.notificationService.SendKnockNotification(approvalURLBase, ipData)

	i.serveKnockPage(rw, ipData.ValidationCode, "Your request requires approval. Please provide the validation code to the administrator.")
}

func (i *IPWhitelistShaper) generateToken(ip string) string {
	h := hmac.New(sha256.New, []byte(i.config.SecretKey))
	data := ip + fmt.Sprintf("%d", time.Now().UnixNano())
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// Assumes lock is held
func (i *IPWhitelistShaper) getUnusedWordList() []string {
	pendingValidationCodes := make(map[string]struct{}, len(i.pendingApprovals))
	for _, pendingIpData := range i.pendingApprovals {
		pendingValidationCodes[pendingIpData.ValidationCode] = struct{}{}
	}

	// Cap on len(wordList) only: pending codes can exceed the word count once the
	// list is exhausted (the "approval" fallback), which would make a difference
	// negative and panic in makeslice.
	unusedWordList := make([]string, 0, len(i.wordList))
	for _, word := range i.wordList {
		if _, exists := pendingValidationCodes[word]; !exists {
			unusedWordList = append(unusedWordList, word)
		}
	}
	return unusedWordList
}

func (i *IPWhitelistShaper) getRandomUnusedWord() string {
	unusedWordList := i.getUnusedWordList()
	if len(unusedWordList) == 0 { return "approval" }
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(unusedWordList))))
	if err != nil { return unusedWordList[0] }
	return unusedWordList[n.Int64()]
}

// evictExpiredLocked removes expired entries from both maps. Assumes the write lock is held.
func (i *IPWhitelistShaper) evictExpiredLocked() {
	now := time.Now()
	for k, v := range i.whitelistedIPs {
		if !now.Before(v.ExpiresAt) {
			delete(i.whitelistedIPs, k)
		}
	}
	for k, v := range i.pendingApprovals {
		if !now.Before(v.ExpiresAt) {
			delete(i.pendingApprovals, k)
		}
	}
}

// serveKnockPage sends the HTML response for the knock endpoint
func (i *IPWhitelistShaper) serveKnockPage(rw http.ResponseWriter, validationCode, message string) {
	html := knockPageHtml(message, validationCode)
	serveHtml(rw, html)
}

// handleApproveRequest serves the approval page on GET (the token lives in the
// URL fragment and never reaches the server) and performs the approval on POST.
func (i *IPWhitelistShaper) handleApproveRequest(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		serveApprovePage(rw)
		return
	}
	if !isSameOrigin(req) {
		fmt.Printf("[%s] WARNING: rejected cross-origin approval POST (Origin: %q)\n", i.name, req.Header.Get("Origin"))
		writeApproveJSON(rw, http.StatusForbidden, approveResult{Status: "error", Message: "Cross-origin approval rejected"})
		return
	}
	i.processApproval(rw, req)
}

// isSameOrigin rejects a POST only when an Origin header is present and its host
// differs from the request host. Clients that omit Origin are allowed — the
// unguessable token is the real protection; this is defence in depth.
func isSameOrigin(req *http.Request) bool {
	origin := req.Header.Get("Origin")
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return parsed.Host == req.Host
}

func (i *IPWhitelistShaper) processApproval(rw http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		writeApproveJSON(rw, http.StatusBadRequest, approveResult{Status: "error", Message: "Invalid request body"})
		return
	}
	ip := req.PostFormValue("ip")
	token := req.PostFormValue("token")
	validationCode := req.PostFormValue("validationCode")

	if ip == "" || token == "" {
		fmt.Printf("[%s] ERROR missing approval parameters. IP: '%s'\n", i.name, ip)
		writeApproveJSON(rw, http.StatusBadRequest, approveResult{Status: "error", Message: "Invalid or missing request parameters"})
		return
	}

	key := i.getIPKey(ip)

	// --- Start Critical Section ---
	i.mutex.Lock()
	defer i.mutex.Unlock()

	// Try to reload state, but don't fail if it doesn't work
	whitelistedIPs, pendingApprovals, _ := i.storageService.Load()
	if whitelistedIPs != nil && pendingApprovals != nil {
		i.whitelistedIPs = whitelistedIPs
		i.pendingApprovals = pendingApprovals
	}
	i.evictExpiredLocked()
	fmt.Printf("[%s] DEBUG State loaded in handleApproveRequest for IP %s (Key: %s). Current pending map size: %d. Content samples: %+v\n",
		i.name, ip, key, len(i.pendingApprovals), maskDebugData(i.pendingApprovals))

	// Pending approvals are bucketed by key (the IPv6 prefix when configured).
	pendingData, exists := i.pendingApprovals[key]
	if !exists {
		if whitelistData, isWhitelisted := i.whitelistedIPs[key]; isWhitelisted {
			fmt.Printf("[%s] INFO IP %s (Key: %s) is already whitelisted, expires at %s\n",
				i.name, ip, key, whitelistData.ExpiresAt.Format(time.RFC3339))
			remainingTime := int(time.Until(whitelistData.ExpiresAt).Seconds())
			if remainingTime < 0 {
				remainingTime = 0
			}
			writeApproveJSON(rw, http.StatusOK, approveResult{Status: "already", IP: ip, ExpiresIn: remainingTime})
			return
		}

		fmt.Printf("[%s] ERROR No pending approval found in current state for IP: %s (Key: %s). Approval attempt failed. Pending map keys: %v\n",
			i.name, ip, key, getMapKeys(i.pendingApprovals))
		writeApproveJSON(rw, http.StatusForbidden, approveResult{Status: "error", Message: "No pending approval found for this address"})
		return
	}

	if pendingData.ValidationID != token {
		fmt.Printf("[%s] ERROR Token mismatch for IP: %s.\n", i.name, ip)
		writeApproveJSON(rw, http.StatusForbidden, approveResult{Status: "error", Message: "Invalid token"})
		return
	}

	if pendingData.ValidationCode != validationCode {
		fmt.Printf("[%s] ERROR Validation code mismatch for IP: %s.\n", i.name, ip)
		writeApproveJSON(rw, http.StatusForbidden, approveResult{Status: "error", Message: "Invalid validation code"})
		return
	}
	// --- End Validation Section ---

	// Whitelist duration is server-controlled; never trust a client-supplied value.
	expirationTime := i.config.ExpirationTime
	ipData := IPData{
		IP:             ip,
		ExpiresAt:      time.Now().Add(time.Duration(expirationTime) * time.Second),
		ValidationID:   token,
		ValidationCode: pendingData.ValidationCode,
	}
	i.whitelistedIPs[key] = ipData

	// Remove all pending approvals for the same prefix
	for pIP := range i.pendingApprovals {
		if i.getIPKey(pIP) == key {
			delete(i.pendingApprovals, pIP)
		}
	}

	// Try to save state, but don't fail if it doesn't work
	if err := i.storageService.Store(i.whitelistedIPs, i.pendingApprovals); err != nil {
		fmt.Printf("[%s] WARNING: Could not save state after approval: %v\n", i.name, err)
	} else {
		fmt.Printf("[%s] INFO State saved synchronously after approval for IP %s.\n", i.name, ip)
	}
	// --- End Critical Section ---

	fmt.Printf("[%s] INFO Approved IP: %s, expiration: %d seconds\n", i.name, ip, expirationTime)
	go i.notificationService.SendApproveConfirmNotification(ipData)

	writeApproveJSON(rw, http.StatusOK, approveResult{Status: "approved", IP: ip, ExpiresIn: expirationTime})
}

// saveState acquires lock and calls saveStateToFile
func (i *IPWhitelistShaper) saveState() error {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return i.storageService.Store(i.whitelistedIPs, i.pendingApprovals)
}

// loadState acquires lock and calls loadStateFromFile
func (i *IPWhitelistShaper) loadState() error {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	whitelistedIPs, pendingApprovals, err := i.storageService.Load()
	if err != nil && !os.IsNotExist(err) {
		fmt.Printf("[%s] WARNING: Could not load state: %v\n", i.name, err)
	}
	if whitelistedIPs != nil && pendingApprovals != nil {
		i.whitelistedIPs = whitelistedIPs
		i.pendingApprovals = pendingApprovals
	}
	return nil
}
