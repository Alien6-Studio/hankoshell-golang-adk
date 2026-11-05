package hankoadk

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/oauth2"
)

// OAuth2RefreshFailureCategory is an allowlisted outcome, never provider text.
type OAuth2RefreshFailureCategory string

const (
	OAuth2RefreshRejectedGrant       OAuth2RefreshFailureCategory = "rejected_grant"
	OAuth2RefreshClientConfig        OAuth2RefreshFailureCategory = "client_configuration"
	OAuth2RefreshProviderUnavailable OAuth2RefreshFailureCategory = "provider_unavailable"
	OAuth2RefreshInvalidResponse     OAuth2RefreshFailureCategory = "invalid_response"
	OAuth2RefreshOutcomeUnknown      OAuth2RefreshFailureCategory = "refresh_outcome_unknown"
)

// OAuth2RefreshFailure contains safe diagnostics only. It deliberately does not
// wrap the original error: oauth2.RetrieveError retains provider bodies, response
// headers and error descriptions. A refresh failure is never safe to replay just
// because it was caused by a timeout or a 503 response.
type OAuth2RefreshFailure struct {
	Category   OAuth2RefreshFailureCategory `json:"category"`
	HTTPStatus int                          `json:"http_status,omitempty"`
	Retryable  bool                         `json:"retryable"`
}

func (failure *OAuth2RefreshFailure) Error() string {
	if failure == nil {
		return "Hanko OAuth2 refresh failed (refresh_outcome_unknown)"
	}
	return fmt.Sprintf("Hanko OAuth2 refresh failed (%s)", safeRefreshCategory(failure.Category))
}

func safeRefreshCategory(category OAuth2RefreshFailureCategory) OAuth2RefreshFailureCategory {
	switch category {
	case OAuth2RefreshRejectedGrant, OAuth2RefreshClientConfig, OAuth2RefreshProviderUnavailable, OAuth2RefreshInvalidResponse:
		return category
	default:
		return OAuth2RefreshOutcomeUnknown
	}
}

// ClassifyOAuth2RefreshError reduces an x/oauth2 token-source error to safe
// metadata. All outcomes are nonretryable because this error alone cannot prove
// that a consuming token POST was never attempted. A nil input returns nil.
func ClassifyOAuth2RefreshError(err error) *OAuth2RefreshFailure {
	if err == nil {
		return nil
	}
	failure := &OAuth2RefreshFailure{Category: OAuth2RefreshOutcomeUnknown}
	var classified *OAuth2RefreshFailure
	if errors.As(err, &classified) && classified != nil {
		failure.Category = safeRefreshCategory(classified.Category)
		if classified.HTTPStatus >= 100 && classified.HTTPStatus <= 599 {
			failure.HTTPStatus = classified.HTTPStatus
		}
		return failure
	}
	var retrieve *oauth2.RetrieveError
	if !errors.As(err, &retrieve) || retrieve == nil {
		return failure
	}
	if retrieve.Response != nil && retrieve.Response.StatusCode >= 100 && retrieve.Response.StatusCode <= 599 {
		failure.HTTPStatus = retrieve.Response.StatusCode
	}
	switch {
	case failure.HTTPStatus == 429 || failure.HTTPStatus >= 500:
		failure.Category = OAuth2RefreshProviderUnavailable
	case failure.HTTPStatus == 400 && retrieve.ErrorCode == "invalid_grant":
		failure.Category = OAuth2RefreshRejectedGrant
	case failure.HTTPStatus == 401 || failure.HTTPStatus == 403 ||
		(failure.HTTPStatus == 400 && (retrieve.ErrorCode == "invalid_client" || retrieve.ErrorCode == "unauthorized_client")):
		failure.Category = OAuth2RefreshClientConfig
	case failure.HTTPStatus >= 200 && failure.HTTPStatus < 300:
		failure.Category = OAuth2RefreshInvalidResponse
	}
	return failure
}

// GuardOAuth2TokenSource serializes one session's source and latches its first
// failure so waiting callers cannot replay a possibly consumed refresh token.
// Construct this wrapper once per session and share it. It is process-local;
// separately constructed sources, persistence, logout and replicas remain the
// application's responsibility. Replace it only after a new sign-in or an
// independently verified recovery, not as an automatic retry mechanism.
func GuardOAuth2TokenSource(source oauth2.TokenSource) oauth2.TokenSource {
	return &guardedOAuth2TokenSource{source: source}
}

type guardedOAuth2TokenSource struct {
	mu      sync.Mutex
	source  oauth2.TokenSource
	failure *OAuth2RefreshFailure
}

func (source *guardedOAuth2TokenSource) Token() (*oauth2.Token, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.failure != nil {
		copy := *source.failure
		return nil, &copy
	}
	if source.source == nil {
		source.failure = &OAuth2RefreshFailure{Category: OAuth2RefreshClientConfig}
	} else {
		token, err := source.source.Token()
		if err != nil {
			source.failure = ClassifyOAuth2RefreshError(err)
		} else if token == nil || strings.TrimSpace(token.AccessToken) == "" {
			source.failure = &OAuth2RefreshFailure{Category: OAuth2RefreshInvalidResponse}
		} else {
			// x/oauth2 reuses its token pointer. Do not let a caller modify that
			// shared credential, expiry or refresh token through the returned value.
			copy := *token
			return &copy, nil
		}
	}
	copy := *source.failure
	return nil, &copy
}
