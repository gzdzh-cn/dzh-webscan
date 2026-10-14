package website

import (
	"context"
	"net/http"
)

type identityKey struct{}

func AuthenticatedUsername(r *http.Request) string {
	value, _ := r.Context().Value(identityKey{}).(string)
	return value
}
func withIdentity(r *http.Request, name string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), identityKey{}, name))
}
