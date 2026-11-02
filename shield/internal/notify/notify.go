// Package notify sends webhook and Slack notifications for pending HITL approvals
// with HMAC-signed, short-lived 1-click approval/denial URLs.
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/Yoosuf01/mcpguard/shield/internal/hitl"
)

var (
	ErrLinkExpired   = errors.New("approval link has expired")
	ErrInvalidSig    = errors.New("invalid approval link signature")
	ErrWebhookFailed = errors.New("webhook delivery failed")
)

type Config struct {
	WebhookURL    string        `yaml:"webhook_url"`
	HMACSecret    string        `yaml:"hmac_secret"`
	PublicBaseURL string        `yaml:"public_base_url"` // e.g. "http://localhost:8081"
	LinkTTL       time.Duration `yaml:"link_ttl"`        // default 15m
}

type Payload struct {
	ApprovalID string         `json:"approval_id"`
	AgentID    string         `json:"agent_id"`
	Subject    string         `json:"subject"`
	Tool       string         `json:"tool"`
	Arguments  map[string]any `json:"arguments"`
	ApproveURL string         `json:"approve_url"`
	DenyURL    string         `json:"deny_url"`
	ExpiresAt  time.Time      `json:"expires_at"`
}

type Notifier struct {
	cfg    Config
	client *http.Client
}

func NewNotifier(cfg Config) *Notifier {
	if cfg.LinkTTL <= 0 {
		cfg.LinkTTL = 15 * time.Minute
	}
	if cfg.PublicBaseURL == "" {
		cfg.PublicBaseURL = "http://localhost:8081"
	}
	return &Notifier{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// SignLink generates a signed URL for 1-click approve or deny.
func (n *Notifier) SignLink(id, action string, exp time.Time) string {
	mac := hmac.New(sha256.New, []byte(n.cfg.HMACSecret))
	data := fmt.Sprintf("%s:%s:%d", id, action, exp.Unix())
	mac.Write([]byte(data))
	sig := hex.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("%s/admin/approvals/%s/decide?action=%s&exp=%d&sig=%s",
		n.cfg.PublicBaseURL, id, action, exp.Unix(), sig)
}

// VerifyLink checks whether the signed parameters are valid and unexpired.
func (n *Notifier) VerifyLink(id, action, expStr, sig string) error {
	expUnix, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return ErrInvalidSig
	}
	if time.Now().Unix() > expUnix {
		return ErrLinkExpired
	}

	mac := hmac.New(sha256.New, []byte(n.cfg.HMACSecret))
	data := fmt.Sprintf("%s:%s:%d", id, action, expUnix)
	mac.Write([]byte(data))
	expected := mac.Sum(nil)

	got, err := hex.DecodeString(sig)
	if err != nil || !hmac.Equal(got, expected) {
		return ErrInvalidSig
	}
	return nil
}

// Notify sends the pending approval payload to the configured webhook.
func (n *Notifier) Notify(ctx context.Context, req *hitl.Request) error {
	if n.cfg.WebhookURL == "" {
		return nil
	}
	exp := time.Now().Add(n.cfg.LinkTTL)
	payload := Payload{
		ApprovalID: req.ID,
		AgentID:    req.AgentID,
		Subject:    req.Subject,
		Tool:       req.Tool,
		Arguments:  req.Arguments,
		ApproveURL: n.SignLink(req.ID, "approve", exp),
		DenyURL:    n.SignLink(req.ID, "deny", exp),
		ExpiresAt:  exp,
	}

	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, n.cfg.WebhookURL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	hreq.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(hreq)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrWebhookFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("%w: HTTP status %d", ErrWebhookFailed, resp.StatusCode)
	}
	return nil
}
