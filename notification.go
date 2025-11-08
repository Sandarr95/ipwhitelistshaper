package ipwhitelistshaper

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type INotificationService interface {
	SendKnockNotification(approvalURLBase string, ipData IPData)
	SendApproveConfirmNotification(ipData IPData)
}

type NotificationService struct {
	name string
	config *Config
	ctx context.Context
}

func newNotificationService(name string, config *Config, ctx context.Context) *NotificationService {
	if config.NotificationURL == "" && config.NotificationURLFile != "" {
		data, err := os.ReadFile(config.NotificationURLFile)
		if err == nil {
		    config.NotificationURL = strings.TrimRight(string(data), "\r\n")
		} else {
			fmt.Printf("[%s] WARNING: notificationURLFile configured but not be readable: %v\n", name, err)
		}
	}
	return &NotificationService{
		name: name,
		config: config,
		ctx: ctx,
	}
}

type GenericNotificationService struct {
	service *NotificationService
}

func (g GenericNotificationService) ExecRequest(message string) {
	values := url.Values{}
	values.Set("message", message)
	body := bytes.NewBufferString(values.Encode())
	ExecRequest(g.service, "POST", "application/x-www-form-urlencoded", body)
}

func (g GenericNotificationService) SendApproveConfirmNotification(ipData IPData) {
	message := fmt.Sprintf("✅ Whitelisted %s for %d seconds", ipData.IP, g.service.config.ExpirationTime)
	g.ExecRequest(message)
}

func (g GenericNotificationService) SendKnockNotification(approvalURLBase string, ipData IPData) {
	approvalLink := ApprovalLink(approvalURLBase, g.service.config.ExpirationTime, ipData)
	message := fmt.Sprintf("Access request from *%s*\nValidation code: `%s`\nApprove link:\n```%s```",
		ipData.IP, ipData.ValidationCode, approvalLink,
	)
	g.ExecRequest(message)
}

type StandardOutNotificationService struct {
	service *NotificationService
}

func (std StandardOutNotificationService) SendApproveConfirmNotification(ipData IPData) {
	message := fmt.Sprintf("✅ Whitelisted %s for %d seconds", ipData.IP, std.service.config.ExpirationTime)
	fmt.Printf("[%s] INFO: [StandardOutNotifcationService]: %s", std.service.name, message)
}

func (std StandardOutNotificationService) SendKnockNotification(approvalURLBase string, ipData IPData) {
	approvalLink := ApprovalLink(approvalURLBase, std.service.config.ExpirationTime, ipData)
	message := fmt.Sprintf("Access request from *%s*\nValidation code: `%s`\nApprove link:\n```%s```",
		ipData.IP, ipData.ValidationCode, approvalLink,
	)
	fmt.Printf("[%s] INFO: [StandardOutNotifcationService]: %s", std.service.name, message)
}

type DiscordNotificationService struct {
	service *NotificationService
}

func (d DiscordNotificationService) ExecRequest(payload any) {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("[%s] ERROR creating Discord payload: %v\n", d.service.name, err)
		return
	}
	body := bytes.NewBuffer(jsonData)
	ExecRequest(d.service, "POST", "application/json", body)
}

func (d DiscordNotificationService) SendApproveConfirmNotification(ipData IPData) {
	message := fmt.Sprintf("✅ Whitelisted %s for %d seconds", ipData.IP, d.service.config.ExpirationTime)
	payload := map[string]string{
		"content": message,
	}
	d.ExecRequest(payload)
}

func (d DiscordNotificationService) SendKnockNotification(approvalURLBase string, ipData IPData) {
	approvalLink := ApprovalLink(approvalURLBase, d.service.config.ExpirationTime, ipData)
	var payload = make(map[string]any)
	if strings.Contains(d.service.config.NotificationURL, "with_components=true") {
		message := fmt.Sprintf("Access request from **%s**\nValidation code: `%s`",
			ipData.IP, ipData.ValidationCode,
		)
		payload = map[string]any{
			"flags": 32768,
			"components": []map[string]any{{
				"type": 10,
				"content": message,
			}, {
				"type": 1,
				"components": []map[string]any{{
					"type": 2,
					"label": "Approve",
					"style": 5,
					"url": approvalLink,
				}},
			}},
		}
	} else {
		message := fmt.Sprintf("Access request from **%s**\nValidation code: `%s`\n\nLink: %s",
			ipData.IP, ipData.ValidationCode, approvalLink,
		)
		payload = map[string]any{
			"content": message,
		}
	}
	d.ExecRequest(payload)
}

type SlackNotificationService struct {
	service *NotificationService
}

func (s SlackNotificationService) ExecRequest(payload any) {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("[%s] ERROR creating Slack payload: %v\n", s.service.name, err)
		return
	}
	body := bytes.NewBuffer(jsonData)
	ExecRequest(s.service, "POST", "application/json", body)
}

func (s SlackNotificationService) SendApproveConfirmNotification(ipData IPData) {
	message := fmt.Sprintf("✅ Whitelisted %s for %d seconds", ipData.IP, s.service.config.ExpirationTime)
	payload := map[string]string{
		"text": message,
	}
	s.ExecRequest(payload)
}

func (s SlackNotificationService) SendKnockNotification(approvalURLBase string, ipData IPData) {
	approvalLink := ApprovalLink(approvalURLBase, s.service.config.ExpirationTime, ipData)
	message := fmt.Sprintf("Access request from *%s*\nValidation code: `%s`",
		ipData.IP, ipData.ValidationCode,
	)
	payload := map[string]any{
        "blocks": []map[string]any{{
			"type": "section",
			"text": map[string]string{
				"type": "mrkdwn",
				"text": message,
			},
		}, {
			"type": "actions",
			"elements": []map[string]any{{
				"type": "button",
				"text": map[string]string{
					"type": "plain_text",
					"text": "Approve",
				},
				"url": approvalLink,
				"action_id": "button-action",
			}},
		}},
	}
	s.ExecRequest(payload)
}

type TelegramNotificationService struct {
	service *NotificationService
}

func (t TelegramNotificationService) ExecRequest(payload any) {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("[%s] ERROR creating Telegram payload: %v\n", t.service.name, err)
		return
	}
	body := bytes.NewBuffer(jsonData)
	ExecRequest(t.service, "POST", "application/json", body)
}

func (t TelegramNotificationService) SendApproveConfirmNotification(ipData IPData) {
	message := fmt.Sprintf("✅ Whitelisted *%s* for *%d* seconds", ipData.IP, t.service.config.ExpirationTime)
	payload := map[string]string{
		"text": message,
		"parse_mode": "MarkdownV2",
	}
	t.ExecRequest(payload)
}

func (t TelegramNotificationService) SendKnockNotification(approvalURLBase string, ipData IPData) {
	approvalLink := ApprovalLink(approvalURLBase, t.service.config.ExpirationTime, ipData)
	message := fmt.Sprintf("Access request from *%s*\nValidation code: `%s`",
		ipData.IP, ipData.ValidationCode,
	)
	payload := map[string]any{
		"text": message,
		"parse_mode": "MarkdownV2",
		"reply_markup": map[string]any{
			"inline_keyboard": [][]map[string]string{
				{
					{
						"text": "Approve",
						"url":  approvalLink,
					},
				},
			},
		},
	}
	t.ExecRequest(payload)
}

func ApprovalLink(approvalURLBase string, expirationTime int, ipData IPData) string {
	return fmt.Sprintf("%s/approve?ip=%s&token=%s&validationCode=%s&expiration=%d",
		approvalURLBase, url.QueryEscape(ipData.IP), url.QueryEscape(ipData.ValidationID),
		url.QueryEscape(ipData.ValidationCode), expirationTime)
}

func ExecRequest(service *NotificationService, method string, contentType string, body io.Reader) {
	req, err := http.NewRequestWithContext(
		service.ctx, method, service.config.NotificationURL, body,
	)
	if err != nil {
		fmt.Printf("[%s] ERROR creating notification request: %v\n", service.name, err)
		return
	}

	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "Traefik-IPWhitelistShaper-Plugin")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		if service.ctx.Err() == nil {
			fmt.Printf("[%s] ERROR sending notification to %s: %v\n",
				service.name, service.config.NotificationURL, err,
			)
		}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		fmt.Printf("[%s] ERROR Notification webhook %s returned error (Status %d): %s\n",
			service.name, service.config.NotificationURL, resp.StatusCode, string(bodyBytes),
		)
	}
}

func initNotificationService(name string, config *Config, ctx context.Context) INotificationService {
	service := newNotificationService(name, config, ctx)
	notificationUrl := strings.ToLower(service.config.NotificationURL)
	isDiscord := strings.Contains(notificationUrl, "discord.com/api/webhooks")
	isSlack := strings.Contains(notificationUrl, "hooks.slack.com/services")
	isTelegram := strings.Contains(notificationUrl, "api.telegram.org/bot")
	isHTTP := strings.Contains(notificationUrl, "http://") || strings.Contains(notificationUrl, "https://")

	if isDiscord {
		return &DiscordNotificationService{ service: service }
	}
	if isSlack {
		return &SlackNotificationService{ service: service }
	}
	if isTelegram {
		return &TelegramNotificationService{ service: service }
	}
	if isHTTP {
		return &GenericNotificationService{ service: service }
	}
	return &StandardOutNotificationService{ service: service }
}
