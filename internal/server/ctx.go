package server

import "context"

type contextKey string

func (c contextKey) String() string {
	return "server context key " + string(c)
}

var (
	contextKeyAuthRequestID = contextKey("auth-request-id")
)

// AuthRequestID gets the authorization request ID from the context.
func AuthRequestID(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(contextKeyAuthRequestID).(string)
	return id, ok
}
