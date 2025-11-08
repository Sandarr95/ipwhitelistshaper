package ipwhitelistshaper

import (
	"fmt"
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
    `, message, validationCode)
	return baseHtml("Approval Required", content)
}

func approvedPageHtml(ip string, expirationTime int) string {
	content := fmt.Sprintf(`
		<div class="container">
			<h1>Access Approved</h1>
			<p><span class="success">IP address <span class="ip-address">%s</span> has been successfully whitelisted.</span></p>
			<p class="expiration">Access will expire in %d seconds.</p>
		</div>
    `, ip, expirationTime)
	return baseHtml("Access Approved", content)
}

func alreadyApprovedPageHtml(ip string, remainingTime int) string {
	content := fmt.Sprintf(`
		<div class="container">
			<h1>Already Approved</h1>
			<p><span class="success">IP address <span class="ip-address">%s</span> is already whitelisted.</span></p>
			<p class="expiration">Access will expire in %d seconds.</p>
		</div>
    `, ip, remainingTime)
	return baseHtml("Already Approved", content)
}

func serveHtml(rw http.ResponseWriter, html string) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte(html))
}
