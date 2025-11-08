package ipwhitelistshaper

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

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

	return ipwhitelistshaper, nil
}

func (i *IPWhitelistShaper) isWhitelisted(clientIP string) bool {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	return isValid(i.whitelistedIPs, clientIP)
}

// handleKnockRequest processes requests to the knock-knock endpoint
func (i *IPWhitelistShaper) handleKnockRequest(rw http.ResponseWriter, req *http.Request, clientIP string) {
	i.mutex.Lock()

	if isValid(i.whitelistedIPs, clientIP) {
		i.mutex.Unlock()
		http.Redirect(rw, req, "/", http.StatusFound)
		return
	}


	if pendingIpData, _ := getValid(i.pendingApprovals, clientIP); pendingIpData != nil {
		validationCode := pendingIpData.ValidationCode
		i.mutex.Unlock()
		if err := i.saveState(); err != nil {
			fmt.Printf("[%s] WARNING: Could not save state during knock re-request: %v\n", i.name, err)
		}
		i.serveKnockPage(rw, validationCode, "An approval request is already pending. Please use the validation code below.")
		return
	}

	ipData := IPData{
		IP:             clientIP,
		ExpiresAt:      time.Now().Add(1 * time.Hour),
		ValidationID:   i.generateToken(clientIP),
		ValidationCode: i.getRandomUnusedWord(),
	}
	i.pendingApprovals[clientIP] = ipData

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
	i.notificationService.SendKnockNotification(approvalURLBase, ipData)

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

	unusedWordList := make([]string, 0, len(i.wordList) - len(pendingValidationCodes))
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
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return unusedWordList[r.Intn(len(unusedWordList))]
}

// serveKnockPage sends the HTML response for the knock endpoint
func (i *IPWhitelistShaper) serveKnockPage(rw http.ResponseWriter, validationCode, message string) {
	html := knockPageHtml(message, validationCode)
	serveHtml(rw, html)
}

// handleApproveRequest processes approval requests
func (i *IPWhitelistShaper) handleApproveRequest(rw http.ResponseWriter, req *http.Request) {
	ipEncoded := req.URL.Query().Get("ip")
	tokenEncoded := req.URL.Query().Get("token")
	validationCodeEncoded := req.URL.Query().Get("validationCode")
	expirationStr := req.URL.Query().Get("expiration")

	ip, err1 := url.QueryUnescape(ipEncoded)
	token, err2 := url.QueryUnescape(tokenEncoded)
	validationCode, err3 := url.QueryUnescape(validationCodeEncoded)

	if err1 != nil || err2 != nil || err3 != nil || ip == "" || token == "" {
		fmt.Printf("[%s] ERROR decoding approval parameters or missing params. IP: '%s', Token: '%s', Code: '%s', IP Err: %v, Token Err: %v, Code Err: %v\n", i.name, ip, token, validationCode, err1, err2, err3)
		http.Error(rw, "Invalid or missing request parameters", http.StatusBadRequest)
		return
	}

	// --- Start Critical Section ---
	i.mutex.Lock()
	defer i.mutex.Unlock()

	// Try to reload state, but don't fail if it doesn't work
	whitelistedIPs, pendingApprovals, _ := i.storageService.Load()
	if whitelistedIPs != nil && pendingApprovals != nil {
		i.whitelistedIPs = whitelistedIPs
		i.pendingApprovals = pendingApprovals
	}
	// Log debugging info
	fmt.Printf("[%s] DEBUG State loaded in handleApproveRequest for IP %s. Current pending map size: %d. Content samples: %+v\n",
		i.name, ip, len(i.pendingApprovals), maskDebugData(i.pendingApprovals))

	// Check if IP and token match the *now loaded* pending approval data
	pendingData, exists := i.pendingApprovals[ip]
	if !exists {
		// NEW CODE: Check if the IP is already whitelisted
		if whitelistData, isWhitelisted := i.whitelistedIPs[ip]; isWhitelisted {
			// IP is already approved, show success page but don't send notification again
			fmt.Printf("[%s] INFO IP %s is already whitelisted, expires at %s\n",
				i.name, ip, whitelistData.ExpiresAt.Format(time.RFC3339))

			// Calculate remaining time
			remainingTime := int(time.Until(whitelistData.ExpiresAt).Seconds())
			if remainingTime < 0 {
				remainingTime = 0
			}

			// Show success page with already whitelisted message
			html := alreadyApprovedPageHtml(ip, remainingTime)
			serveHtml(rw, html)
			return
		}

		// Original error message for IP not found in either list
		fmt.Printf("[%s] ERROR No pending approval found in current state for IP: %s (Token: %s). Approval attempt failed. Pending map keys: %v\n",
			i.name, ip, token, getMapKeys(i.pendingApprovals))
		http.Error(rw, "Invalid token or IP address: No pending approval found", http.StatusForbidden)
		return
	}

	if pendingData.ValidationID != token {
		fmt.Printf("[%s] ERROR Token mismatch for IP: %s. Expected in state: '%s', Got from URL: '%s'\n", i.name, ip, pendingData.ValidationID, token)
		http.Error(rw, "Invalid token or IP address: Token mismatch", http.StatusForbidden)
		return
	}

	if pendingData.ValidationCode != validationCode {
		fmt.Printf("[%s] ERROR Validation code mismatch for IP: %s. Expected in state: '%s', Got from URL: '%s'\n", i.name, ip, pendingData.ValidationCode, validationCode)
		http.Error(rw, "Invalid validation code", http.StatusForbidden)
		return
	}
	// --- End Validation Section ---

	expirationTime := i.config.ExpirationTime
	if expirationStr != "" {
		_, err := fmt.Sscanf(expirationStr, "%d", &expirationTime)
		if err != nil || expirationTime <= 0 {
			expirationTime = i.config.ExpirationTime
		}
	}

	expiresAt := time.Now().Add(time.Duration(expirationTime) * time.Second)
	ipData := IPData{
		IP:             ip,
		ExpiresAt:      expiresAt,
		ValidationID:   token,
		ValidationCode: pendingData.ValidationCode,
	}
	i.whitelistedIPs[ip] = ipData
	delete(i.pendingApprovals, ip) // Remove from pending

	// Try to save state, but don't fail if it doesn't work
	if err := i.storageService.Store(i.whitelistedIPs, i.pendingApprovals); err != nil {
		fmt.Printf("[%s] WARNING: Could not save state after approval: %v\n", i.name, err)
	} else {
		fmt.Printf("[%s] INFO State saved synchronously after approval for IP %s.\n", i.name, ip)
	}
	// --- End Critical Section ---

	fmt.Printf("[%s] INFO Approved IP: %s, expiration: %d seconds\n", i.name, ip, expirationTime)
	go i.notificationService.SendApproveConfirmNotification(ipData)

	// Return success message
	html := approvedPageHtml(ip, expirationTime)
	serveHtml(rw, html)
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
