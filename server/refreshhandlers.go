package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/server/internal"
	"github.com/dexidp/dex/storage"
)

func contains(arr []string, item string) bool {
	for _, itemFromArray := range arr {
		if itemFromArray == item {
			return true
		}
	}
	return false
}

type refreshError struct {
	msg  string
	code int
	desc string
}

func (r *refreshError) Error() string {
	return fmt.Sprintf("refresh token error: status %d, %q %s", r.code, r.msg, r.desc)
}

func newInternalServerError() *refreshError {
	return &refreshError{msg: errInvalidRequest, desc: "", code: http.StatusInternalServerError}
}

func newBadRequestError(desc string) *refreshError {
	return &refreshError{msg: errInvalidRequest, desc: desc, code: http.StatusBadRequest}
}

func (s *Server) refreshTokenErrHelper(w http.ResponseWriter, err *refreshError) {
	s.tokenErrHelper(w, err.msg, err.desc, err.code)
}

func (s *Server) extractRefreshTokenFromRequest(r *http.Request) (*internal.RefreshToken, *refreshError) {
	code := r.PostFormValue("refresh_token")
	if code == "" {
		return nil, newBadRequestError("No refresh token is found in request.")
	}

	token := new(internal.RefreshToken)
	if err := internal.Unmarshal(code, token); err != nil {
		// For backward compatibility, assume the refresh_token is a raw refresh token ID
		// if it fails to decode.
		//
		// Because refresh_token values that aren't unmarshable were generated by servers
		// that don't have a Token value, we'll still reject any attempts to claim a
		// refresh_token twice.
		token = &internal.RefreshToken{RefreshId: code, Token: ""}
	}

	return token, nil
}

type refreshContext struct {
	storageToken *storage.RefreshToken
	requestToken *internal.RefreshToken

	connector     Connector
	connectorData []byte

	scopes []string
}

// getRefreshTokenFromStorage checks that refresh token is valid and exists in the storage and gets its info
func (s *Server) getRefreshTokenFromStorage(clientID string, token *internal.RefreshToken, now time.Time) (*refreshContext, *refreshError) {
	refreshCtx := refreshContext{requestToken: token}
	invalidErr := newBadRequestError("Refresh token is invalid or has already been claimed by another client.")

	// Get RefreshToken
	refresh, err := s.storage.GetRefresh(token.RefreshId)
	if err != nil {
		if err != storage.ErrNotFound {
			s.logger.Errorf("failed to get refresh token: %v", err)
			return nil, newInternalServerError()
		}
		return nil, invalidErr
	}

	if refresh.ClientID != clientID {
		s.logger.Errorf("client %s trying to claim token for client %s", clientID, refresh.ClientID)
		// According to https://datatracker.ietf.org/doc/html/rfc6749#section-5.2 Dex should respond with an
		//  invalid grant error if token has already been claimed by another client.
		return nil, &refreshError{msg: errInvalidGrant, desc: invalidErr.desc, code: http.StatusBadRequest}
	}

	if refresh.Token != token.Token {
		switch {
		case !s.refreshTokenPolicy.AllowedToReuse(refresh.LastUsed, now):
			fallthrough
		case refresh.ObsoleteToken != token.Token:
			fallthrough
		case refresh.ObsoleteToken == "":
			s.logger.Errorf("refresh token with id %s claimed twice", refresh.ID)
			return nil, invalidErr
		}
	}

	expiredErr := newBadRequestError("Refresh token expired.")
	if s.refreshTokenPolicy.CompletelyExpired(refresh.CreatedAt) {
		s.logger.Errorf("refresh token with id %s expired", refresh.ID)
		return nil, expiredErr
	}

	if s.refreshTokenPolicy.ExpiredBecauseUnused(refresh.LastUsed) {
		s.logger.Errorf("refresh token with id %s expired due to inactivity", refresh.ID)
		return nil, expiredErr
	}

	refreshCtx.storageToken = &refresh

	// Get Connector
	refreshCtx.connector, err = s.getConnector(refresh.ConnectorID)
	if err != nil {
		s.logger.Errorf("connector with ID %q not found: %v", refresh.ConnectorID, err)
		return nil, newInternalServerError()
	}

	// Get Connector Data
	session, err := s.storage.GetOfflineSessions(refresh.Claims.UserID, refresh.ConnectorID)
	switch {
	case err != nil:
		if err != storage.ErrNotFound {
			s.logger.Errorf("failed to get offline session: %v", err)
			return nil, newInternalServerError()
		}
	case len(refresh.ConnectorData) > 0:
		// Use the old connector data if it exists, should be deleted once used
		refreshCtx.connectorData = refresh.ConnectorData
	default:
		refreshCtx.connectorData = session.ConnectorData
	}

	return &refreshCtx, nil
}

func (s *Server) getRefreshScopes(r *http.Request, refresh *storage.RefreshToken) ([]string, *refreshError) {
	// Per the OAuth2 spec, if the client has omitted the scopes, default to the original
	// authorized scopes.
	//
	// https://tools.ietf.org/html/rfc6749#section-6
	scope := r.PostFormValue("scope")

	if scope == "" {
		return refresh.Scopes, nil
	}

	requestedScopes := strings.Fields(scope)
	var unauthorizedScopes []string

	// Per the OAuth2 spec, if the client has omitted the scopes, default to the original
	// authorized scopes.
	//
	// https://tools.ietf.org/html/rfc6749#section-6
	for _, requestScope := range requestedScopes {
		if !contains(refresh.Scopes, requestScope) {
			unauthorizedScopes = append(unauthorizedScopes, requestScope)
		}
	}

	if len(unauthorizedScopes) > 0 {
		desc := fmt.Sprintf("Requested scopes contain unauthorized scope(s): %q.", unauthorizedScopes)
		return nil, newBadRequestError(desc)
	}

	return requestedScopes, nil
}

func (s *Server) refreshWithConnector(ctx context.Context, rCtx *refreshContext, ident connector.Identity, now time.Time) (connector.Identity, *refreshError) {
	// Can the connector refresh the identity? If so, attempt to refresh the data
	// in the connector.
	//
	// TODO(ericchiang): We may want a strict mode where connectors that don't implement
	// this interface can't perform refreshing.
	if refreshConn, ok := rCtx.connector.Connector.(connector.RefreshConnector); ok {
		s.logger.Debugf("connector data before refresh: %s", ident.ConnectorData)

		newIdent, err := refreshConn.Refresh(ctx, parseScopes(rCtx.scopes), ident)
		if err != nil {
			s.logger.Errorf("failed to refresh identity: %v", err)
			return ident, newInternalServerError()
		}

		return newIdent, nil
	}
	return ident, nil
}

// updateOfflineSession updates offline session in the storage
func (s *Server) updateOfflineSession(refresh *storage.RefreshToken, ident connector.Identity, lastUsed time.Time) *refreshError {
	offlineSessionUpdater := func(old storage.OfflineSessions) (storage.OfflineSessions, error) {
		if old.Refresh[refresh.ClientID].ID != refresh.ID {
			return old, errors.New("refresh token invalid")
		}

		old.Refresh[refresh.ClientID].LastUsed = lastUsed
		if len(ident.ConnectorData) > 0 {
			old.ConnectorData = ident.ConnectorData
		}

		s.logger.Debugf("saved connector data: %s %s", ident.UserID, ident.ConnectorData)

		return old, nil
	}

	// Update LastUsed time stamp in refresh token reference object
	// in offline session for the user.
	err := s.storage.UpdateOfflineSessions(refresh.Claims.UserID, refresh.ConnectorID, offlineSessionUpdater)
	if err != nil {
		s.logger.Errorf("failed to update offline session: %v", err)
		return newInternalServerError()
	}

	return nil
}

// updateRefreshToken updates refresh token and offline session in the storage
func (s *Server) updateRefreshToken(ctx context.Context, rCtx *refreshContext, now time.Time) (*internal.RefreshToken, connector.Identity, *refreshError) {
	var rerr *refreshError

	newToken := &internal.RefreshToken{
		Token:     rCtx.requestToken.Token,
		RefreshId: rCtx.requestToken.RefreshId,
	}

	lastUsed := now

	ident := connector.Identity{
		UserID:            rCtx.storageToken.Claims.UserID,
		Username:          rCtx.storageToken.Claims.Username,
		PreferredUsername: rCtx.storageToken.Claims.PreferredUsername,
		Email:             rCtx.storageToken.Claims.Email,
		EmailVerified:     rCtx.storageToken.Claims.EmailVerified,
		Groups:            rCtx.storageToken.Claims.Groups,
		ConnectorData:     rCtx.connectorData,
	}

	refreshTokenUpdater := func(old storage.RefreshToken) (storage.RefreshToken, error) {
		rotationEnabled := s.refreshTokenPolicy.RotationEnabled()
		reusingAllowed := s.refreshTokenPolicy.AllowedToReuse(old.LastUsed, now)

		switch {
		case !rotationEnabled && reusingAllowed:
			// If rotation is disabled and the offline session was updated not so long ago - skip further actions.
			return old, nil

		case rotationEnabled && reusingAllowed:
			if old.Token != rCtx.requestToken.Token && old.ObsoleteToken != rCtx.requestToken.Token {
				return old, errors.New("refresh token claimed twice")
			}

			// Return previously generated token for all requests with an obsolete tokens
			if old.ObsoleteToken == rCtx.requestToken.Token {
				newToken.Token = old.Token
			}

			// Do not update last used time for offline session if token is allowed to be reused
			lastUsed = old.LastUsed
			ident.ConnectorData = nil
			return old, nil

		case rotationEnabled && !reusingAllowed:
			if old.Token != rCtx.requestToken.Token {
				return old, errors.New("refresh token claimed twice")
			}

			// Issue new refresh token
			old.ObsoleteToken = old.Token
			newToken.Token = storage.NewID()
		}

		old.Token = newToken.Token
		old.LastUsed = lastUsed

		// ConnectorData has been moved to OfflineSession
		old.ConnectorData = []byte{}

		// Call  only once if there is a request which is not in the reuse interval.
		// This is required to avoid multiple calls to the external IdP for concurrent requests.
		// Dex will call the connector's Refresh method only once if request is not in reuse interval.
		ident, rerr = s.refreshWithConnector(ctx, rCtx, ident, now)
		if rerr != nil {
			return old, rerr
		}

		// Update the claims of the refresh token.
		//
		// UserID intentionally ignored for now.
		old.Claims.Username = ident.Username
		old.Claims.PreferredUsername = ident.PreferredUsername
		old.Claims.Email = ident.Email
		old.Claims.EmailVerified = ident.EmailVerified
		old.Claims.Groups = ident.Groups

		return old, nil
	}

	// Update refresh token in the storage.
	err := s.storage.UpdateRefreshToken(rCtx.storageToken.ID, refreshTokenUpdater)
	if err != nil {
		s.logger.Errorf("failed to update refresh token: %v", err)
		return nil, ident, newInternalServerError()
	}

	rerr = s.updateOfflineSession(rCtx.storageToken, ident, lastUsed)
	if rerr != nil {
		return nil, ident, rerr
	}

	return newToken, ident, nil
}

// handleRefreshToken handles a refresh token request https://tools.ietf.org/html/rfc6749#section-6
// this method is the entrypoint for refresh tokens handling
func (s *Server) handleRefreshToken(w http.ResponseWriter, r *http.Request, client storage.Client) {
	now := time.Now()
	token, rerr := s.extractRefreshTokenFromRequest(r)
	if rerr != nil {
		s.refreshTokenErrHelper(w, rerr)
		return
	}

	rCtx, rerr := s.getRefreshTokenFromStorage(client.ID, token, now)
	if rerr != nil {
		s.refreshTokenErrHelper(w, rerr)
		return
	}

	rCtx.scopes, rerr = s.getRefreshScopes(r, rCtx.storageToken)
	if rerr != nil {
		s.refreshTokenErrHelper(w, rerr)
		return
	}

	newToken, ident, rerr := s.updateRefreshToken(r.Context(), rCtx, now)
	if rerr != nil {
		s.refreshTokenErrHelper(w, rerr)
		return
	}

	claims := storage.Claims{
		UserID:            ident.UserID,
		Username:          ident.Username,
		PreferredUsername: ident.PreferredUsername,
		Email:             ident.Email,
		EmailVerified:     ident.EmailVerified,
		Groups:            ident.Groups,
	}

	accessToken, err := s.newAccessToken(client.ID, claims, rCtx.scopes, rCtx.storageToken.Nonce, rCtx.storageToken.ConnectorID)
	if err != nil {
		s.logger.Errorf("failed to create new access token: %v", err)
		s.refreshTokenErrHelper(w, newInternalServerError())
		return
	}

	idToken, expiry, err := s.newIDToken(client.ID, claims, rCtx.scopes, rCtx.storageToken.Nonce, accessToken, "", rCtx.storageToken.ConnectorID)
	if err != nil {
		s.logger.Errorf("failed to create ID token: %v", err)
		s.refreshTokenErrHelper(w, newInternalServerError())
		return
	}

	rawNewToken, err := internal.Marshal(newToken)
	if err != nil {
		s.logger.Errorf("failed to marshal refresh token: %v", err)
		s.refreshTokenErrHelper(w, newInternalServerError())
		return
	}

	resp := s.toAccessTokenResponse(idToken, accessToken, rawNewToken, expiry)
	s.writeAccessToken(w, resp)
}
