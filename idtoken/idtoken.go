package idtoken

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// Claims represents the set of JWT claims for the user.
//
// https://openid.net/specs/openid-connect-core-1_0.html#Claims
type Claims struct {
	// REQUIRED. Issuer Identifier for the Issuer of the response. The iss value
	// is a case sensitive URL using the https scheme that contains scheme,
	// host, and optionally, port number and path components and no query or
	// fragment components.
	Issuer string `json:"iss,omitempty"`
	// REQUIRED. Subject Identifier. A locally unique and never reassigned
	// identifier within the Issuer for the End-User, which is intended to be
	// consumed by the Client, e.g., 24400320 or
	// AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4. It MUST NOT exceed 255 ASCII
	// characters in length. The sub value is a case sensitive string.
	Subject string `json:"sub,omitempty"`
	// REQUIRED. Audience(s) that this ID Token is intended for. It MUST contain
	// the OAuth 2.0 client_id of the Relying Party as an audience value. It MAY
	// also contain identifiers for other audiences.
	Audience Audience `json:"aud,omitempty"`
	// REQUIRED. Expiration time on or after which the ID Token MUST NOT be
	// accepted for processing. The processing of this parameter requires that
	// the current date/time MUST be before the expiration date/time listed in
	// the value. Implementers MAY provide for some small leeway, usually no
	// more than a few minutes, to account for clock skew.
	Expiry UnixTime `json:"exp,omitempty"`
	// OPTIONAL. The "nbf" (not before) claim identifies the time before which
	// the JWT MUST NOT be accepted for processing.  The processing of the "nbf"
	// claim requires that the current date/time MUST be after or equal to the
	// not-before date/time listed in the "nbf" claim.  Implementers MAY provide
	// for some small leeway, usually no more than a few minutes, to account for
	// clock skew.  Its value MUST be a number containing a NumericDate value.
	NotBefore UnixTime `json:"nbf,omitempty"`
	// REQUIRED. Time at which the JWT was issued.
	IssuedAt UnixTime `json:"iat,omitempty"`
	// Time when the End-User authentication occurred. Its value is a JSON
	// number representing the number of seconds from 1970-01-01T0:0:0Z as
	// measured in UTC until the date/time. When a max_age request is made or
	// when auth_time is requested as an Essential Claim, then this Claim is
	// REQUIRED; otherwise, its inclusion is OPTIONAL. (The auth_time Claim
	// semantically corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] auth_time
	// response parameter.)
	AuthTime UnixTime `json:"auth_time,omitempty"`
	// String value used to associate a Client session with an ID Token, and to
	// mitigate replay attacks. The value is passed through unmodified from the
	// Authentication Request to the ID Token. If present in the ID Token,
	// Clients MUST verify that the nonce Claim Value is equal to the value of
	// the nonce parameter sent in the Authentication Request. If present in the
	// Authentication Request, Authorization Servers MUST include a nonce Claim
	// in the ID Token with the Claim Value being the nonce value sent in the
	// Authentication Request. Authorization Servers SHOULD perform no other
	// processing on nonce values used. The nonce value is a case sensitive
	// string.
	Nonce string `json:"nonce,omitempty"`
	// OPTIONAL. Authentication Context Class Reference. String specifying an
	// Authentication Context Class Reference value that identifies the
	// Authentication Context Class that the authentication performed satisfied.
	// The value "0" indicates the End-User authentication did not meet the
	// requirements of ISO/IEC 29115 [ISO29115] level 1. Authentication using a
	// long-lived browser cookie, for instance, is one example where the use of
	// "level 0" is appropriate. Authentications with level 0 SHOULD NOT be used
	// to authorize access to any resource of any monetary value. (This
	// corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] nist_auth_level 0.) An
	// absolute URI or an RFC 6711 [RFC6711] registered name SHOULD be used as
	// the acr value; registered names MUST NOT be used with a different meaning
	// than that which is registered. Parties using this claim will need to
	// agree upon the meanings of the values used, which may be
	// context-specific. The acr value is a case sensitive string.
	ACR string `json:"acr,omitempty"`
	// OPTIONAL. Authentication Methods References. JSON array of strings that
	// are identifiers for authentication methods used in the authentication.
	// For instance, values might indicate that both password and OTP
	// authentication methods were used. The definition of particular values to
	// be used in the amr Claim is beyond the scope of this specification.
	// Parties using this claim will need to agree upon the meanings of the
	// values used, which may be context-specific. The amr value is an array of
	// case sensitive strings.
	AMR []string `json:"amr,omitempty"`
	// OPTIONAL. Authorized party - the party to which the ID Token was issued.
	// If present, it MUST contain the OAuth 2.0 Client ID of this party. This
	// Claim is only needed when the ID Token has a single audience value and
	// that audience is different than the authorized party. It MAY be included
	// even when the authorized party is the same as the sole audience. The azp
	// value is a case sensitive string containing a StringOrURI value.
	AZP string `json:"azp,omitempty"`

	// Extra are additional claims, that the standard claims will be merged in
	// to. If a key is overridden here, the struct value wins.
	Extra map[string]interface{} `json:"-"`

	// keep the raw data here, so we can unmarshal in to custom structs
	raw json.RawMessage
}

func (i Claims) MarshalJSON() ([]byte, error) {
	// avoid recursing on this method
	type ids Claims
	id := ids(i)

	sj, err := json.Marshal(&id)
	if err != nil {
		return nil, err
	}

	sm := map[string]interface{}{}
	if err := json.Unmarshal(sj, &sm); err != nil {
		return nil, err
	}

	om := map[string]interface{}{}

	for k, v := range i.Extra {
		om[k] = v
	}

	for k, v := range sm {
		om[k] = v
	}

	return json.Marshal(om)
}

func (i *Claims) UnmarshalJSON(b []byte) error {
	type ids Claims
	id := ids{}

	if err := json.Unmarshal(b, &id); err != nil {
		return err
	}

	em := map[string]interface{}{}

	if err := json.Unmarshal(b, &em); err != nil {
		return err
	}

	for _, f := range []string{
		"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "azp",
	} {
		delete(em, f)
	}

	if len(em) > 0 {
		id.Extra = em
	}

	id.raw = b

	*i = Claims(id)

	return nil
}

// Unmarshal unpacks the raw JSON data from this token into the passed type.
func (i *Claims) Unmarshal(into interface{}) error {
	if i.raw == nil {
		// gracefully handle the weird case where the user might want to call
		// this on a struct of their own creation, rather than one retrieved
		// from a remote source
		b, err := json.Marshal(i)
		if err != nil {
			return err
		}
		i.raw = b
	}
	return json.Unmarshal(i.raw, into)
}

// Audience represents a OIDC ID Token's Audience field.
type Audience []string

// Contains returns true if a passed audence is found in the token's set
func (a Audience) Contains(aud string) bool {
	for _, ia := range a {
		if ia == aud {
			return true
		}
	}
	return false
}

func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

func (a *Audience) UnmarshalJSON(b []byte) error {
	var ua interface{}
	if err := json.Unmarshal(b, &ua); err != nil {
		return err
	}

	switch ja := ua.(type) {
	case string:
		*a = []string{ja}
	case []interface{}:
		aa := make([]string, len(ja))
		for i, ia := range ja {
			sa, ok := ia.(string)
			if !ok {
				return fmt.Errorf("failed to unmarshal audience, expected []string but found %T", ia)
			}
			aa[i] = sa
		}
		*a = aa
	default:
		return fmt.Errorf("failed to unmarshal audience, expected string or []string but found %T", ua)
	}

	return nil
}

// UnixTime represents the number representing the number of seconds from
// 1970-01-01T0:0:0Z as measured in UTC until the date/time. This is the type
// IDToken uses to represent dates
type UnixTime int64

// NewUnixTime creates a UnixTime from the given Time, t
func NewUnixTime(t time.Time) UnixTime {
	return UnixTime(t.Unix())
}

// Time returns the *time.Time this represents
func (u UnixTime) Time() time.Time {
	return time.Unix(int64(u), 0)
}

func (u UnixTime) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatInt(int64(u), 10)), nil
}

func (u *UnixTime) UnmarshalJSON(b []byte) error {
	p, err := strconv.ParseInt(string(b), 10, 64)
	if err != nil {
		return fmt.Errorf("failed to parse UnixTime: %v", err)
	}
	*u = UnixTime(p)
	return nil
}
