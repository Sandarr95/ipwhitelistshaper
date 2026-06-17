package ipwhitelistshaper

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
)

func baseHtml(title string, content string) string {
	return fmt.Sprintf(`
		<!DOCTYPE html>
		<html lang="en">
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<title>%s</title>
			<style>
				body { font-family: system-ui, sans-serif; background-color: #f0f4f8; color: #333; padding: 20px; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
				.container { max-width: 500px; width: 100%%; background-color: #fff; border-radius: 8px; padding: 30px; box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1); text-align: center; }
				h1 { color: #2c3e50; margin-bottom: 15px; }
				p { color: #555; margin-bottom: 25px; line-height: 1.6; }
				.highlight { background-color: #e0f2fe; padding: 8px 12px; border-radius: 4px; font-weight: bold; font-size: 1.2em; color: #0b72e0; display: inline-block; margin-top: 10px; border: 1px solid #b3d4fc; }
			</style>
		</head>
		<body>%s</body>
		</html>
	`, title, content)
}

func knockPageHtml(message string, validationCode string) string {
	content := fmt.Sprintf(`
	    <div class="container">
			<h1>Approval Required</h1>
			<p>%s</p>
			<p>Validation code: <span class="highlight">%s</span></p>
			<p>An administrator needs to approve your access using this code.</p>
		</div>
    `, html.EscapeString(message), html.EscapeString(validationCode))
	return baseHtml("Approval Required", content)
}

// approveResult is the JSON returned by the POST /approve endpoint and rendered
// client-side by the approval page.
type approveResult struct {
	Status    string `json:"status"` // "approved", "already" or "error"
	IP        string `json:"ip"`
	ExpiresIn int    `json:"expiresIn"`
	Message   string `json:"message"`
}

// approvePageHtml is served on GET /approve. The token travels in the URL
// fragment (never sent to the server), so this page reads it client-side,
// scrubs it from history, and POSTs the approval. Result text is rendered with
// textContent only — never innerHTML — so a hostile fragment cannot inject markup.
func approvePageHtml() string {
	content := `
		<div class="container">
			<h1>Approving&hellip;</h1>
			<p id="status">Validating your approval request&hellip;</p>
			<noscript><p>JavaScript is required to approve access requests.</p></noscript>
		</div>
		<script>
		(function () {
			var statusEl = document.getElementById('status');
			function show(msg) { statusEl.textContent = msg; }
			var params = new URLSearchParams(location.hash.replace(/^#!?/, ''));
			var ip = params.get('ip');
			var token = params.get('token');
			history.replaceState(null, '', location.pathname);
			if (!ip || !token) {
				show('Nothing to approve — this link is missing its approval data or has already been used.');
				return;
			}
			var body = new URLSearchParams();
			body.set('ip', ip);
			body.set('token', token);
			body.set('validationCode', params.get('validationCode') || '');
			fetch(location.pathname, {
				method: 'POST',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
				body: body.toString()
			}).then(function (resp) {
				return resp.json();
			}).then(function (d) {
				if (d.status === 'approved') {
					show('Access approved for ' + d.ip + '. It will expire in ' + d.expiresIn + ' seconds.');
				} else if (d.status === 'already') {
					show(d.ip + ' is already whitelisted (expires in ' + d.expiresIn + ' seconds).');
				} else {
					show('Approval failed: ' + (d.message || 'unknown error') + '.');
				}
			}).catch(function () {
				show('Approval failed: could not reach the server.');
			});
		})();
		</script>
	`
	return baseHtml("Approve Access", content)
}

func serveApprovePage(rw http.ResponseWriter) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Referrer-Policy", "no-referrer")
	rw.Header().Set("X-Frame-Options", "DENY")
	rw.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte(approvePageHtml()))
}

func writeApproveJSON(rw http.ResponseWriter, status int, result approveResult) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.Header().Set("Cache-Control", "no-store")
	rw.WriteHeader(status)
	json.NewEncoder(rw).Encode(result)
}

func serveHtml(rw http.ResponseWriter, html string) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte(html))
}
