package authflow

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/server/tokens"
	"github.com/dexidp/dex/storage"
)

func (h *Handler) trySessionLogin(ctx context.Context, r *http.Request, w http.ResponseWriter, authReq *storage.AuthRequest) bool {
	session := h.Sessions.ValidAuthSession(ctx, w, r, authReq)
	return h.trySessionLoginWithSession(ctx, r, w, authReq, session)
}

// trySessionLoginWithSession completes the login from an existing session: a
// direct session for the client, or, failing that, an SSO session shared by
// another client. SSO sharing is unidirectional — a source sharing with a target
// does not mean the target shares back. Returns false when no session applies.
func (h *Handler) trySessionLoginWithSession(ctx context.Context, r *http.Request, w http.ResponseWriter, authReq *storage.AuthRequest, session *storage.AuthSession) bool {
	if session == nil {
		return false
	}

	now := h.Now()

	_, directLogin := session.ClientStates[authReq.ClientID]
	if !directLogin {
		// No direct session for this client — try SSO from a sharing client.
		sourceState := h.Sessions.FindSSO(ctx, session, authReq.ClientID)
		if sourceState == nil {
			return false
		}

		// Create a new client state for the target client via SSO. It carries the
		// source's authentication time: the user did not authenticate again here.
		if err := h.Storage.UpdateAuthSession(ctx, session.ID, func(old storage.AuthSession) (storage.AuthSession, error) {
			if old.ClientStates == nil {
				old.ClientStates = make(map[string]*storage.ClientAuthState)
			}
			old.ClientStates[authReq.ClientID] = &storage.ClientAuthState{
				AuthenticatedAt: sourceState.AuthenticatedAt,
				LastActivity:    now,
				ViaSSO:          true,
			}
			old.LastActivity = now
			old.IdleExpiry = h.Sessions.IdleExpiry(now)
			return old, nil
		}); err != nil {
			h.Logger.ErrorContext(ctx, "session: failed to create SSO client state", "err", err)
			return false
		}

		h.Logger.DebugContext(ctx, "session: SSO login from sharing client",
			"user_id", session.UserID, "connector_id", session.ConnectorID, "client_id", authReq.ClientID)
	}

	// Load identity from storage (same path for direct and SSO login).
	ui, err := h.Storage.GetUserIdentity(ctx, session.UserID, session.ConnectorID)
	if err != nil {
		h.Logger.ErrorContext(ctx, "session: failed to get user identity", "err", err)
		return false
	}

	// Check max_age: if the user's last authentication is too old, force re-auth.
	if authReq.MaxAge >= 0 {
		if now.Sub(ui.LastLogin) > time.Duration(authReq.MaxAge)*time.Second {
			return false
		}
	}

	// The cached claims only cover the scopes the connector was asked for when
	// the user last really logged in. If this request needs more, fall back to a
	// full connector login, which refreshes the cache.
	if !h.sessionCoversRequest(ctx, authReq, &ui) {
		return false
	}

	if directLogin {
		h.Logger.DebugContext(ctx, "session: re-authenticated from session",
			"session_id", session.ID, "user_id", session.UserID)
	}

	return h.finishSessionLogin(ctx, r, w, authReq, session, &ui, now)
}

// sessionCoversRequest reports whether the connector data cached for ui is enough
// for the scopes authReq asks for. Only scopes that change what the connector
// returns or stores are checked:
//
//   - groups: connectors such as LDAP only look groups up when asked, so the
//     cached groups are trustworthy only if a past login requested them.
//   - offline_access: for a refresh-capable connector, finalizeLogin saves the
//     OfflineSessions (and its ConnectorData) that refresh tokens depend on.
//     Session reuse skips finalizeLogin, so require that an earlier login did it
//     and that the offline session still exists.
//
// Rows written before UserIdentity.ConnectorScopes existed cover nothing.
func (h *Handler) sessionCoversRequest(ctx context.Context, authReq *storage.AuthRequest, ui *storage.UserIdentity) bool {
	if scopesContain(authReq.Scopes, tokens.ScopeGroups) &&
		!containsString(ui.ConnectorScopes, storage.ConnectorScopeGroups) {
		h.Logger.DebugContext(ctx, "session: cached identity lacks groups, full login required",
			"user_id", ui.UserID, "connector_id", ui.ConnectorID, "client_id", authReq.ClientID)
		return false
	}

	if scopesContain(authReq.Scopes, tokens.ScopeOfflineAccess) {
		conn, err := h.Connectors.Get(ctx, ui.ConnectorID)
		if err != nil {
			h.Logger.ErrorContext(ctx, "session: failed to get connector", "connector_id", ui.ConnectorID, "err", err)
			return false
		}
		if _, ok := conn.Connector.(connector.RefreshConnector); ok {
			if !containsString(ui.ConnectorScopes, storage.ConnectorScopeOfflineAccess) {
				h.Logger.DebugContext(ctx, "session: offline_access not yet processed, full login required",
					"user_id", ui.UserID, "connector_id", ui.ConnectorID, "client_id", authReq.ClientID)
				return false
			}
			if _, err := h.Storage.GetOfflineSessions(ctx, ui.UserID, ui.ConnectorID); err != nil {
				if !errors.Is(err, storage.ErrNotFound) {
					h.Logger.ErrorContext(ctx, "session: failed to get offline session", "err", err)
				}
				return false
			}
		}
	}
	return true
}

// finishSessionLogin completes a session-based login (direct or SSO) by updating the auth request
// with the user's identity, refreshing session activity, and returning the appropriate redirect URL.
func (h *Handler) finishSessionLogin(ctx context.Context, r *http.Request, w http.ResponseWriter, authReq *storage.AuthRequest, session *storage.AuthSession, ui *storage.UserIdentity, now time.Time) bool {
	claims := storage.Claims{
		UserID:            ui.Claims.UserID,
		Username:          ui.Claims.Username,
		PreferredUsername: ui.Claims.PreferredUsername,
		Email:             ui.Claims.Email,
		EmailVerified:     ui.Claims.EmailVerified,
		Groups:            ui.Claims.Groups,
	}

	// Update AuthRequest with stored identity and auth_time from last login.
	if err := h.Storage.UpdateAuthRequest(ctx, authReq.ID, func(a storage.AuthRequest) (storage.AuthRequest, error) {
		a.LoggedIn = true
		a.Claims = claims
		a.ConnectorID = session.ConnectorID
		a.AuthTime = ui.LastLogin
		return a, nil
	}); err != nil {
		h.Logger.ErrorContext(ctx, "session: failed to update auth request", "err", err)
		return false
	}

	// Update session activity.
	_ = h.Storage.UpdateAuthSession(ctx, session.ID, func(old storage.AuthSession) (storage.AuthSession, error) {
		old.LastActivity = now
		old.IdleExpiry = h.Sessions.IdleExpiry(now)
		if cs, ok := old.ClientStates[authReq.ClientID]; ok {
			cs.LastActivity = now
		}
		return old, nil
	})

	// Re-read to get the updated AuthRequest (LoggedIn, Claims, ConnectorID set above),
	// then let the shared decision pick the next step.
	updated, err := h.Storage.GetAuthRequest(ctx, authReq.ID)
	if err != nil {
		h.Logger.ErrorContext(ctx, "session: failed to get auth request", "err", err)
		return false
	}
	http.Redirect(w, r, h.buildContinueURL(updated), http.StatusSeeOther)
	return true
}
