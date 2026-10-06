package authflow

import (
	"context"
	"crypto"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/connector/mock"
	"github.com/dexidp/dex/server/connectors"
	"github.com/dexidp/dex/storage"
)

// passwordOnlyConnector is a connector that cannot refresh.
type passwordOnlyConnector struct{}

func (passwordOnlyConnector) Prompt() string { return "" }

func (passwordOnlyConnector) Login(context.Context, connector.Scopes, string, string) (connector.Identity, bool, error) {
	return connector.Identity{}, false, nil
}

// useConnector registers conn as the "mock" connector in both storage and cache.
func useConnector(t *testing.T, s *sessionTestServer, conn connector.Connector) {
	t.Helper()
	require.NoError(t, s.Storage.CreateConnector(t.Context(), storage.Connector{ID: "mock", Type: "mock", ResourceVersion: "1"}))
	s.Connectors.Set("mock", connectors.Connector{Type: "mock", ResourceVersion: "1", Connector: conn})
}

// newScopedRequest stores an auth request for client-1 asking for scopes.
func newScopedRequest(t *testing.T, s *sessionTestServer, scopes ...string) storage.AuthRequest {
	t.Helper()
	req := storage.AuthRequest{
		ID:          storage.NewID(),
		ClientID:    "client-1",
		ConnectorID: "mock",
		Scopes:      scopes,
		RedirectURI: "http://localhost/callback",
		MaxAge:      -1,
		HMACKey:     storage.NewHMACKey(crypto.SHA256),
		Expiry:      s.Now().Add(10 * time.Minute),
	}
	require.NoError(t, s.Storage.CreateAuthRequest(t.Context(), req))
	return req
}

func setConnectorScopes(t *testing.T, s *sessionTestServer, scopes []string) {
	t.Helper()
	require.NoError(t, s.Storage.UpdateUserIdentity(t.Context(), "user-1", "mock", func(u storage.UserIdentity) (storage.UserIdentity, error) {
		u.ConnectorScopes = scopes
		return u, nil
	}))
}

func reuse(t *testing.T, s *sessionTestServer, req storage.AuthRequest) bool {
	t.Helper()
	return s.trySessionLogin(t.Context(), sessionCookieRequest("test-nonce"), httptest.NewRecorder(), &req)
}

func TestSessionReuseScopeCoverage(t *testing.T) {
	const (
		groups  = storage.ConnectorScopeGroups
		offline = storage.ConnectorScopeOfflineAccess
	)

	tests := []struct {
		name        string
		conn        connector.Connector
		cached      []string // UserIdentity.ConnectorScopes; nil emulates a legacy row
		offlineSess bool     // whether an OfflineSessions row exists
		scopes      []string
		wantReuse   bool
	}{
		{"no special scopes, legacy row", mock.NewCallbackConnector(nil), nil, false, []string{"openid", "email"}, true},
		{"groups requested, legacy row", mock.NewCallbackConnector(nil), nil, false, []string{"openid", "groups"}, false},
		{"groups requested, groups not fetched", mock.NewCallbackConnector(nil), []string{offline}, true, []string{"openid", "groups"}, false},
		{"groups requested, groups fetched", mock.NewCallbackConnector(nil), []string{groups}, false, []string{"openid", "groups"}, true},
		{"offline_access, legacy row", mock.NewCallbackConnector(nil), nil, false, []string{"openid", "offline_access"}, false},
		{"offline_access, processed and session exists", mock.NewCallbackConnector(nil), []string{offline}, true, []string{"openid", "offline_access"}, true},
		{"offline_access, marker but offline session gone", mock.NewCallbackConnector(nil), []string{offline}, false, []string{"openid", "offline_access"}, false},
		{"offline_access, session exists but marker missing", mock.NewCallbackConnector(nil), []string{groups}, true, []string{"openid", "offline_access"}, false},
		{"offline_access on non-refresh connector", passwordOnlyConnector{}, nil, false, []string{"openid", "offline_access"}, true},
		{"groups and offline_access, both covered", mock.NewCallbackConnector(nil), []string{groups, offline}, true, []string{"openid", "groups", "offline_access"}, true},
		{"groups and offline_access, one missing", mock.NewCallbackConnector(nil), []string{groups}, true, []string{"openid", "groups", "offline_access"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestSessionServer(t)
			s.SkipApproval = true
			setupSessionLoginFixture(t, s)
			useConnector(t, s, tc.conn)
			setConnectorScopes(t, s, tc.cached)
			if tc.offlineSess {
				require.NoError(t, s.Storage.CreateOfflineSessions(t.Context(), storage.OfflineSessions{
					UserID: "user-1", ConnID: "mock", Refresh: map[string]*storage.RefreshTokenRef{},
				}))
			}

			assert.Equal(t, tc.wantReuse, reuse(t, s, newScopedRequest(t, s, tc.scopes...)))
		})
	}
}

// A session opened by a client without groups must not serve a client that wants
// groups; after a full login for the latter, both are served from the session
// and the groups are kept.
func TestSessionReuseUpgradesAfterFullLogin(t *testing.T) {
	ctx := t.Context()
	s := newTestSessionServer(t)
	s.SkipApproval = true
	setupSessionLoginFixture(t, s)
	useConnector(t, s, mock.NewCallbackConnector(nil))

	ident := connector.Identity{UserID: "user-1", Username: "testuser", Email: "test@example.com", Groups: []string{"admins"}}
	noGroups := connector.Identity{UserID: "user-1", Username: "testuser", Email: "test@example.com"}

	// Gitea-like client without groups: legacy row, still reused.
	assert.True(t, reuse(t, s, newScopedRequest(t, s, "openid", "email")))

	// Grafana-like client with groups: not covered, full login required.
	assert.False(t, reuse(t, s, newScopedRequest(t, s, "openid", "groups")))

	// The full login asks the connector for groups and upgrades the cache.
	full := newScopedRequest(t, s, "openid", "groups")
	_, err := s.finalizeLogin(ctx, ident, full, nil)
	require.NoError(t, err)
	ui, err := s.Storage.GetUserIdentity(ctx, "user-1", "mock")
	require.NoError(t, err)
	assert.Equal(t, []string{storage.ConnectorScopeGroups}, ui.ConnectorScopes)
	assert.Equal(t, []string{"admins"}, ui.Claims.Groups)

	// Now the groups client is served from the session with the cached groups.
	again := newScopedRequest(t, s, "openid", "groups")
	require.True(t, reuse(t, s, again))
	got, err := s.Storage.GetAuthRequest(ctx, again.ID)
	require.NoError(t, err)
	assert.True(t, got.LoggedIn)
	assert.Equal(t, []string{"admins"}, got.Claims.Groups)

	// The client without groups is still served too.
	assert.True(t, reuse(t, s, newScopedRequest(t, s, "openid", "email")))

	// A later full login without groups must not wipe the cached groups, nor the
	// record that they were fetched.
	_, err = s.finalizeLogin(ctx, noGroups, newScopedRequest(t, s, "openid"), nil)
	require.NoError(t, err)
	ui, err = s.Storage.GetUserIdentity(ctx, "user-1", "mock")
	require.NoError(t, err)
	assert.Equal(t, []string{"admins"}, ui.Claims.Groups)
	assert.Equal(t, []string{storage.ConnectorScopeGroups}, ui.ConnectorScopes)
	assert.True(t, reuse(t, s, newScopedRequest(t, s, "openid", "groups")))
}

func TestFinalizeLoginRecordsConnectorScopes(t *testing.T) {
	ctx := t.Context()
	ident := connector.Identity{UserID: "user-1", Username: "testuser", Email: "test@example.com"}

	t.Run("offline_access on a refresh connector is recorded and unioned", func(t *testing.T) {
		s := newTestSessionServer(t)
		setupSessionLoginFixture(t, s)
		conn := mock.NewCallbackConnector(nil)
		useConnector(t, s, conn)

		_, err := s.finalizeLogin(ctx, ident, newScopedRequest(t, s, "openid", "offline_access"), conn)
		require.NoError(t, err)
		ui, err := s.Storage.GetUserIdentity(ctx, "user-1", "mock")
		require.NoError(t, err)
		assert.Equal(t, []string{storage.ConnectorScopeOfflineAccess}, ui.ConnectorScopes)
		_, err = s.Storage.GetOfflineSessions(ctx, "user-1", "mock")
		require.NoError(t, err)

		_, err = s.finalizeLogin(ctx, ident, newScopedRequest(t, s, "openid", "groups"), conn)
		require.NoError(t, err)
		ui, err = s.Storage.GetUserIdentity(ctx, "user-1", "mock")
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{storage.ConnectorScopeOfflineAccess, storage.ConnectorScopeGroups}, ui.ConnectorScopes)
	})

	t.Run("offline_access on a non-refresh connector is not recorded", func(t *testing.T) {
		s := newTestSessionServer(t)
		setupSessionLoginFixture(t, s)

		_, err := s.finalizeLogin(ctx, ident, newScopedRequest(t, s, "openid", "offline_access"), passwordOnlyConnector{})
		require.NoError(t, err)
		ui, err := s.Storage.GetUserIdentity(ctx, "user-1", "mock")
		require.NoError(t, err)
		assert.Empty(t, ui.ConnectorScopes)
	})

	t.Run("new identity records scopes", func(t *testing.T) {
		s := newTestSessionServer(t)
		setupSessionLoginFixture(t, s)
		require.NoError(t, s.Storage.DeleteUserIdentity(ctx, "user-1", "mock"))

		_, err := s.finalizeLogin(ctx, ident, newScopedRequest(t, s, "openid", "groups"), nil)
		require.NoError(t, err)
		ui, err := s.Storage.GetUserIdentity(ctx, "user-1", "mock")
		require.NoError(t, err)
		assert.Equal(t, []string{storage.ConnectorScopeGroups}, ui.ConnectorScopes)
	})
}
