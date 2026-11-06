package hankoadk

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

type principalContextKey struct{}

// PrincipalFromContext returns only a principal authenticated by BearerMiddleware.
func PrincipalFromContext(ctx context.Context) (*Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(*Principal)
	return principal, ok
}

// BearerMiddleware authenticates one bearer header and optionally applies a
// product-owned authorization policy. No cookie or query token fallback exists.
// Safe denial categories distinguish authorization (403) from authentication (401).
func BearerMiddleware(verify func(context.Context, string) (*Principal, error), authorize func(context.Context, *Principal) error) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fail := func(status int, category string) {
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("Content-Type", "application/json")
				if status == http.StatusUnauthorized {
					w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
				}
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": category})
			}
			values := r.Header.Values("Authorization")
			if len(values) != 1 || len(values[0]) > maxAccessTokenBytes+7 {
				fail(http.StatusUnauthorized, "invalid_token")
				return
			}
			parts := strings.Split(values[0], " ")
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
				fail(http.StatusUnauthorized, "invalid_token")
				return
			}
			if verify == nil {
				fail(http.StatusServiceUnavailable, "authentication_unavailable")
				return
			}
			principal, err := verify(r.Context(), parts[1])
			if err != nil || principal == nil || principal.Issuer == "" || principal.Subject == "" {
				fail(http.StatusUnauthorized, "invalid_token")
				return
			}
			if authorize != nil {
				if err := authorize(r.Context(), principal); err != nil {
					var denial *ApplicationAccessError
					if errors.As(err, &denial) {
						fail(http.StatusForbidden, string(denial.Category))
					} else {
						fail(http.StatusForbidden, "access_denied")
					}
					return
				}
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalContextKey{}, principal)))
		})
	}
}
