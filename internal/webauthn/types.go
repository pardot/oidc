package webauthn

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"

	"github.com/pkg/errors"
	"github.com/ugorji/go/codec"
)

type UserVerificationRequirement string

const (
	UserVerificationPreferred UserVerificationRequirement = "preferred"
	UserVerificationRequired  UserVerificationRequirement = "required"
)

type PublicKeyCredentialType string

const (
	PublicKeyCredentialTypePublicKey PublicKeyCredentialType = "public-key"
)

type COSEAlgorithmIdentifier int8

// See: <https://www.iana.org/assignments/cose/cose.xhtml#algorithms>
const (
	COSEAlgorithmES256 COSEAlgorithmIdentifier = -7
	COSEAlgorithmES384 COSEAlgorithmIdentifier = -35
	COSEAlgorithmES512 COSEAlgorithmIdentifier = -36

	// TODO: Support PS/RS algorithms (note: they don't encode signatures with ASN.1)
	// COSEAlgorithmPS256 COSEAlgorithmIdentifier = -37
	// COSEAlgorithmPS384 COSEAlgorithmIdentifier = -38
	// COSEAlgorithmPS512 COSEAlgorithmIdentifier = -39
	// TODO: RS{256,384,512}? They aren't standard yet
)

type AttestationConveyancePreference string

// See: <https://w3c.github.io/webauthn/#enumdef-attestationconveyancepreference>
const (
	AttestationConveyancePreferenceNone     AttestationConveyancePreference = "none"
	AttestationConveyancePreferenceIndirect AttestationConveyancePreference = "indirect"
	AttestationConveyancePreferenceDirect   AttestationConveyancePreference = "direct"
)

// See: <https://w3c.github.io/webauthn/#assertion-options>
type PublicKeyCredentialRequestOptions struct {
	RPID             string                      `json:"rpId,omitempty"`
	Challenge        []byte                      `json:"challenge"`
	UserVerification UserVerificationRequirement `json:"userVerification,omitempty"`
}

// See: <https://w3c.github.io/webauthn/#dictionary-makecredentialoptions>
type PublicKeyCredentialCreationOptions struct {
	RP   PublicKeyCredentialRpEntity   `json:"rp"`
	User PublicKeyCredentialUserEntity `json:"user"`

	Challenge        []byte                          `json:"challenge"`
	PubKeyCredParams []PublicKeyCredentialParameters `json:"pubKeyCredParams"`

	AuthenticatorSelection AuthenticatorSelectionCriteria  `json:"authenticatorSelection"`
	Attestation            AttestationConveyancePreference `json:"attestation"`
}

// See: <https://w3c.github.io/webauthn/#dictdef-publickeycredentialrpentity>
type PublicKeyCredentialRpEntity struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name"`
	Icon string `json:"icon"`
}

// See: <https://w3c.github.io/webauthn/#dictdef-publickeycredentialuserentity>
type PublicKeyCredentialUserEntity struct {
	Id          []byte `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

// See: <https://w3c.github.io/webauthn/#dictdef-publickeycredentialparameters>
type PublicKeyCredentialParameters struct {
	Type      PublicKeyCredentialType `json:"type"`
	Algorithm COSEAlgorithmIdentifier `json:"alg"`
}

// See: <https://w3c.github.io/webauthn/#dictdef-authenticatorselectioncriteria>
type AuthenticatorSelectionCriteria struct {
	RequireResidentKey bool                        `json:"requireResidentKey"`
	UserVerification   UserVerificationRequirement `json:"userVerification"`
}

// See: <https://w3c.github.io/webauthn/#iface-pkcredential>
type PublicKeyCredential struct {
	ID       string                  `json:"id"`
	RawID    []byte                  `json:"rawId"`
	Type     PublicKeyCredentialType `json:"type"`
	Response AuthenticatorResponse   `json:"response"`
}

// See: <https://w3c.github.io/webauthn/#authenticatorresponse>
type AuthenticatorResponse struct {
	// ClientDataJSON is defined for all response types
	ClientDataJSON []byte `json:"clientDataJSON"`

	// AttestationObject is defined when a new public key is being enrolled
	// See: <https://w3c.github.io/webauthn/#dom-authenticatorattestationresponse-attestationobject>
	AttestationObject *AttestationObject `json:"attestationObject,omitempty"`

	// AuthenticatorData, Signature and UserHandle are defined when an existing
	// public key is used for authentication
	// See: <https://w3c.github.io/webauthn/#iface-authenticatorassertionresponse>
	AuthenticatorData *AuthenticatorData `json:"authenticatorData,omitempty"`
	Signature         []byte             `json:"signature,omitempty"`
	UserHandle        []byte             `json:"userHandle,omitempty"`
}

type AttestationObject struct {
	AuthenticatorData AuthenticatorData `codec:"authData"`
	Format            string            `codec:"fmt"`
}

func (o *AttestationObject) UnmarshalJSON(data []byte) error {
	data = bytes.Trim(data, `"`)

	enc := base64.StdEncoding
	b := make([]byte, enc.DecodedLen(len(data)))
	n, err := enc.Decode(b, data)
	if err != nil {
		return err
	}

	return codec.NewDecoderBytes(b[:n], &codec.CborHandle{}).Decode(o)
}

// See: <https://w3c.github.io/webauthn/#attestation-object>
type AuthenticatorData struct {
	RPIDHash            []byte         // 32 bytes
	Flags               byte           // 1 byte
	Counter             uint32         // 4 bytes
	AAGUID              []byte         // 16 bytes
	CredentialID        []byte         // Variable length
	CredentialPublicKey *COSEPublicKey // Variable length
	// Extensions are left unparsed for now
}

func (d *AuthenticatorData) UnmarshalJSON(data []byte) error {
	data = bytes.Trim(data, `"`)

	enc := base64.StdEncoding
	b := make([]byte, enc.DecodedLen(len(data)))
	n, err := enc.Decode(b, data)
	if err != nil {
		return err
	}

	return d.UnmarshalBinary(b[:n])
}

func (d *AuthenticatorData) MarshalBinary() ([]byte, error) {
	// Need to define this so codec recognizes us as a BinaryMarshaler, but nothing actually uses it yet
	return nil, errors.New("not implemented")
}

func (d *AuthenticatorData) UnmarshalBinary(data []byte) error {
	if len(data) < 37 {
		return errors.New("invalid auth data")
	}

	// Decode all the fixed-length things directly
	d.RPIDHash = data[0:32]
	d.Flags = data[32]
	d.Counter = binary.BigEndian.Uint32(data[33:37])

	// Fields beyond this point are optional
	// https://w3c.github.io/webauthn/#authenticator-data
	if len(data) >= 55 {
		d.AAGUID = data[37:53]

		// Credential ID length: 2-byte uint16
		l := binary.BigEndian.Uint16(data[53:55])
		rest := data[55:]
		if len(rest) < int(l) {
			return errors.New("invalid auth data credential length")
		}
		d.CredentialID = rest[0:int(l)]

		rest = rest[l:]
		d.CredentialPublicKey = new(COSEPublicKey)
		if err := codec.NewDecoderBytes(rest, &codec.CborHandle{}).Decode(d.CredentialPublicKey); err != nil {
			return errors.Wrap(err, "failed to decode public key")
		}

		// TODO: Extensions
	}

	return nil
}

func (d *AuthenticatorData) IsUserPresent() bool {
	return d.Flags&(0x01<<0) > 0
}

func (d *AuthenticatorData) IsUserVerified() bool {
	return d.Flags&(0x01<<2) > 0
}

func (d *AuthenticatorData) IsAttestedCredentialDataIncluded() bool {
	return d.Flags&(0x01<<6) > 0
}

func (d *AuthenticatorData) HasExtensions() bool {
	return d.Flags&(0x01<<7) > 0
}

type COSEPublicKey struct {
	_struct bool                    `codec:",int"`
	Type    COSEAlgorithmIdentifier `codec:"3"`
	KeyType int8                    `codec:"1"`
	Curve   int8                    `gorm:"not null" codec:"-1"`
	X       []byte                  `gorm:"not null" codec:"-2"`
	Y       []byte                  `gorm:"not null" codec:"-3"`
}
