package hankoadk

import (
	"fmt"
	"math"
	"time"
)

const (
	accessClockSkewSeconds   = 30
	maxAccessLifetimeSeconds = 3600
	maxSafeNumericDate       = 9007199254740991
	maxAccessTokenBytes      = 64 * 1024
)

// validateAccessClaims supplements signature/issuer/audience verification.
func validateAccessClaims(claims map[string]any, now time.Time) error {
	if claims["hanko_token_use"] != "access" {
		return fmt.Errorf("hanko resource server requires an access token")
	}
	exp, ok := accessNumericDate(claims["exp"])
	if !ok || exp <= now.Unix() {
		return fmt.Errorf("hanko access token expiration is missing, invalid or expired")
	}
	iat, ok := accessNumericDate(claims["iat"])
	if !ok || iat > now.Unix()+accessClockSkewSeconds {
		return fmt.Errorf("hanko access token issuance is missing, invalid or in the future")
	}
	if exp <= iat || exp-iat > maxAccessLifetimeSeconds {
		return fmt.Errorf("hanko access token lifetime must be positive and at most one hour")
	}
	if value, exists := claims["nbf"]; exists {
		nbf, ok := accessNumericDate(value)
		if !ok || nbf > now.Unix()+accessClockSkewSeconds || nbf >= exp {
			return fmt.Errorf("hanko access token not-before claim is invalid or in the future")
		}
	}
	return nil
}

func accessNumericDate(value any) (int64, bool) {
	number, ok := value.(float64)
	if !ok || !(number > 0 && number <= maxSafeNumericDate && math.Trunc(number) == number) {
		return 0, false
	}
	return int64(number), true
}
