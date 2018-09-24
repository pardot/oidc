package deci

type UserVerificationRequirement string

const (
	UserVerificationPreferred UserVerificationRequirement = "preferred"
	UserVerificationRequired  UserVerificationRequirement = "required"
)

type PublicKeyCredentialType string

const (
	PublicKeyCredentialTypePublicKey PublicKeyCredentialType = "public-key"
)

type COSEAlgorithmIdentifier int

// See: <https://www.iana.org/assignments/cose/cose.xhtml#algorithms>
const (
	COSEAlgorithmES256 COSEAlgorithmIdentifier = -7
	COSEAlgorithmES384 COSEAlgorithmIdentifier = -35
	COSEAlgorithmES512 COSEAlgorithmIdentifier = -36
	COSEAlgorithmPS256 COSEAlgorithmIdentifier = -37
	COSEAlgorithmPS384 COSEAlgorithmIdentifier = -38
	COSEAlgorithmPS512 COSEAlgorithmIdentifier = -39
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
	Challenge        []byte                      `json:"challenge"`
	UserVerification UserVerificationRequirement `json:"userVerification"`
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
	Type PublicKeyCredentialType `json:"type"`
	Alg  COSEAlgorithmIdentifier `json:"alg"`
}

// See: <https://w3c.github.io/webauthn/#dictdef-authenticatorselectioncriteria>
type AuthenticatorSelectionCriteria struct {
	RequireResidentKey bool                        `json:"requireResidentKey"`
	UserVerification   UserVerificationRequirement `json:"userVerification"`
}
