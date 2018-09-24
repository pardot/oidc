package deci

type UserVerificationRequirement string

const (
	UserVerificationRequired UserVerificationRequirement = "required"
)

type PublicKeyCredentialRequestOptions struct {
	Challenge        []byte                      `json:"challenge"`
	UserVerification UserVerificationRequirement `json:"userVerification"`
}
