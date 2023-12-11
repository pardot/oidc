package core

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Session represents an invidual user session, bound to a given client.
//
// The Session object is tagged for serialization using JSON tags.
type Session interface {
	// GetID returns the unique identifier for tracking this session.
	ID() string
	// Expiry returns the time this session expires. Implementations
	// should garbage collect expired sessions, as this implementation doesn't
	Expiry() time.Time
}

// SessionManager is used to track the state of the session across it's
// lifecycle.
type SessionManager interface {
	// NewID should return a new, unique identifier to be used for a session. It
	// should be hard to guess/brute force
	NewID() string
	// GetSession should return the current session state for the given session
	// ID. It should be deserialized/written in to into. If the session does not
	// exist, found should be false with no error.
	GetSession(ctx context.Context, sessionID string, into Session) (found bool, err error)
	// PutSession should persist the new state of the session
	PutSession(context.Context, Session) error
	// DeleteSession should remove the corresponding session.
	DeleteSession(ctx context.Context, sessionID string) error
}

const (
	sessionVer2 = "session/v2"
)

type versionedSession struct {
	Version string          `json:"version"`
	Session json.RawMessage `json:"session"`

	// when we return a session, it's expected to obey the interface. to make it
	// easier to handle this, on objects created by us wedge the data here
	sess *sessionV2
}

func (v *versionedSession) ID() string {
	return v.sess.ID
}

func (v *versionedSession) Expiry() time.Time {
	return v.sess.Expiry
}

type sessionStage string

const (
	// A request to authenticate someone has been received, but upstream has not
	// authenticated the user.
	sessionStageRequested sessionStage = "requested"
	// Code flow was requested, and a code has been issued.
	sessionStageCode sessionStage = "code"
	// An access token has been issued to the user, but the session is not for
	// offline access (aka no refresh token)
	sessionStageAccessTokenIssued sessionStage = "access_token_issued"
	// An access token has been issued, along with a refresh token.
	sessionStageRefreshable sessionStage = "refreshable"
)

// Session represents an authenticated user from the time they are issued a
// code, until their last refresh/access token expires.s
type sessionV2 struct {
	ID string `json:"id,omitempty"`
	// stage represents where in the overall lifecycle this session is.
	Stage sessionStage `json:"stage,omitempty"`
	// request stores information about the original request we received.
	Request *sessAuthRequest `json:"request,omitempty"`
	// tracks the details this session was actually authorized for
	Authorization *sessAuthorization `json:"authorization,omitempty"`
	// the client ID this session is bound to.
	ClientID string `json:"client_id,omitempty"`
	// The authorization code that was issued for the code flow.
	AuthCode *accessToken `json:"auth_code,omitempty"`
	// if the auth code has been previously redeemed. If we get a subsequent
	// redemption, we should drop the whole session
	//
	// https://tools.ietf.org/html/rfc6819#section-4.4.1.1
	AuthCodeRedeemed bool `json:"auth_code_redeemed,omitempty"`
	// The current access token, if one has been issued. It's expiration time
	// should always be checked.
	AccessToken *accessToken `json:"access_token,omitempty"`
	// The currently valid refresh token for this session. I
	RefreshToken *accessToken `json:"refresh_token,omitempty"`
	// The time the whole session should be expired at. It should be garbage
	// collected at this time.
	Expiry time.Time `json:"expiry,omitempty"`
}

type authRequestResponseType string

const (
	authRequestResponseTypeUnknown authRequestResponseType = "unknown"
	authRequestResponseTypeCode    authRequestResponseType = "code"
	authRequestResponseTypeToken   authRequestResponseType = "token"
)

// AuthRequest represents the information that the caller requested
// authorization with.
type sessAuthRequest struct {
	RedirectURI  string                  `json:"redirect_uri,omitempty"`
	State        string                  `json:"state,omitempty"`
	Scopes       []string                `json:"scopes,omitempty"`
	Nonce        string                  `json:"nonce,omitempty"`
	ResponseType authRequestResponseType `json:"response_type,omitempty"`
}

type accessToken struct {
	// bcrypted version of the token that was issued to the user
	Bcrypted []byte `json:"bcrypted,omitempty"`
	// when this token expires
	Expiry time.Time `json:"expires_at,omitempty"`
}

// sessAuthorization represents the information that the authentication process
// authorized the user for.
type sessAuthorization struct {
	Scopes       []string  `json:"scopes,omitempty"`
	ACR          string    `json:"acr,omitempty"`
	AMR          []string  `json:"amr,omitempty"`
	AuthorizedAt time.Time `json:"authorized_at,omitempty"`
}

// we need something that looks like the interface we can pass in to get, but
// captures the bare information. The methods should never be called in this
// usage, so we should be OK.
type rawSession struct {
	json.RawMessage
}

func (*rawSession) ID() string {
	panic("should not be called")
}

func (*rawSession) Expiry() time.Time {
	panic("should not be called")
}

func getSession(ctx context.Context, sm SessionManager, sessionID string) (*sessionV2, error) {
	vsess := versionedSession{}
	found, err := sm.GetSession(ctx, sessionID, &vsess)
	if err != nil {
		return nil, fmt.Errorf("getting raw session data: %v", err)
	}
	if !found {
		return nil, nil
	}

	if vsess.Version != sessionVer2 {
		return nil, fmt.Errorf("only session version %s supported, but found %s", sessionVer2, vsess.Version)
	}

	sess := sessionV2{}
	if err := json.Unmarshal(vsess.Session, &sess); err != nil {
		return nil, fmt.Errorf("unmarshaling session: %v", err)
	}
	return &sess, nil
}

func putSession(ctx context.Context, sm SessionManager, sess *sessionV2) error {
	// serialize to db, making sure we populate the private record so they other side can fetch ID

	ser, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("marshaling session: %v", err)
	}

	vsess := &versionedSession{
		Version: sessionVer2,
		Session: json.RawMessage(ser),
		sess:    sess,
	}

	if err := sm.PutSession(ctx, vsess); err != nil {
		return err
	}

	return nil
}
