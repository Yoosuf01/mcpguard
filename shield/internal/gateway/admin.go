package gateway

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"

	"fmt"
	"github.com/Yoosuf01/mcpguard/shield/internal/identity"
	"github.com/Yoosuf01/mcpguard/shield/internal/notify"
)

// AdminHandler exposes the human controls: approve/deny parked calls and the
// kill switch. Protect it with a separate admin token and bind it to an
// internal interface in production.
func (g *Gateway) AdminHandler(adminToken string, rev identity.Revocations) http.Handler {
	mux := http.NewServeMux()
	auth := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if adminToken == "" || subtle.ConstantTimeCompare([]byte(got), []byte(adminToken)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}
	mux.HandleFunc("GET /admin/approvals", auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, g.engine.Approvals().List())
	}))
	decide := func(approve bool) http.HandlerFunc {
		return auth(func(w http.ResponseWriter, r *http.Request) {
			req, ok := g.engine.Approvals().Decide(r.PathValue("id"), approve)
			if !ok {
				http.Error(w, "no pending approval with that id", http.StatusNotFound)
				return
			}
			writeJSON(w, http.StatusOK, req)
		})
	}
	mux.HandleFunc("POST /admin/approvals/{id}/approve", decide(true))
	mux.HandleFunc("POST /admin/approvals/{id}/deny", decide(false))
	mux.HandleFunc("POST /admin/revoke", auth(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			SessionID string `json:"session_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.SessionID == "" {
			http.Error(w, "session_id required", http.StatusBadRequest)
			return
		}
		rev.Revoke(r.Context(), body.SessionID)
		writeJSON(w, http.StatusOK, map[string]any{"revoked": body.SessionID})
	}))

	// Sentinel Console (HTML5 single-page application)
	serveConsole := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; script-src 'unsafe-inline'; style-src 'unsafe-inline'")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(ConsoleHTML))
	}
	mux.HandleFunc("GET /admin/console", serveConsole)
	mux.HandleFunc("GET /admin/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/" || r.URL.Path == "/admin" {
			serveConsole(w, r)
			return
		}
		http.NotFound(w, r)
	})

	// Audit trail endpoint
	mux.HandleFunc("GET /admin/audit", auth(func(w http.ResponseWriter, r *http.Request) {
		if g.auditLog != nil {
			writeJSON(w, http.StatusOK, g.auditLog.Events())
		} else {
			writeJSON(w, http.StatusOK, []any{})
		}
	}))

	// Tool pins endpoint
	mux.HandleFunc("GET /admin/pins", auth(func(w http.ResponseWriter, r *http.Request) {
		pinsMap := map[string]string{}
		if lister, ok := g.pins.(interface{ List() map[string]string }); ok {
			pinsMap = lister.List()
		}
		writeJSON(w, http.StatusOK, pinsMap)
	}))

	// Signed 1-click decision endpoint for Slack/webhooks
	mux.HandleFunc("GET /admin/approvals/{id}/decide", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		action := r.URL.Query().Get("action")
		expStr := r.URL.Query().Get("exp")
		sig := r.URL.Query().Get("sig")

		if g.opts.HMACSecret == "" {
			http.Error(w, "signed approval links not configured", http.StatusBadRequest)
			return
		}
		n := notify.NewNotifier(notify.Config{HMACSecret: g.opts.HMACSecret})
		if err := n.VerifyLink(id, action, expStr, sig); err != nil {
			http.Error(w, "invalid or expired approval link: "+err.Error(), http.StatusForbidden)
			return
		}

		approve := action == "approve"
		req, ok := g.engine.Approvals().Decide(id, approve)
		if !ok {
			http.Error(w, "approval already resolved or not found", http.StatusNotFound)
			return
		}
		statusText := "APPROVED"
		if !approve {
			statusText = "DENIED"
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html><body style="font-family:sans-serif;padding:2rem;"><h2>MCPGuard Approval Decision</h2><p>Request <strong>%s</strong> for tool <code>%s</code> has been <strong>%s</strong>.</p></body></html>`, req.ID, req.Tool, statusText)
	})

	return mux
}
