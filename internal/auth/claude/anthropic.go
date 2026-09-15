package claude

// PKCECodes holds PKCE verification codes for OAuth2 PKCE flow
type PKCECodes struct {
	// CodeVerifier is the cryptographically random string used to correlate
	// the authorization request to the token request
	CodeVerifier string `json:"code_verifier"`
	// CodeChallenge is the SHA256 hash of the code verifier, base64url-encoded
	CodeChallenge string `json:"code_challenge"`
}

// ClaudeTokenData holds OAuth token information from Anthropic
type ClaudeTokenData struct {
	// AccessToken is the OAuth2 access token for API access.
	AccessToken string `json:"access_token"`
	// RefreshToken is used to obtain new access tokens.
	RefreshToken string `json:"refresh_token"`
	// Email is the Anthropic account email.
	Email string `json:"email"`
	// AccountUUID identifies the Anthropic account returned by OAuth.
	AccountUUID string `json:"account_uuid"`
	// OrganizationUUID identifies the Anthropic organization returned by OAuth.
	OrganizationUUID string `json:"organization_uuid"`
	// OrganizationName is the display name returned by OAuth.
	OrganizationName      string `json:"organization_name"`
	DisplayName           string `json:"display_name"`
	AvatarURL             string `json:"avatar_url"`
	AccountCreatedAt      string `json:"account_created_at"`
	OrganizationType      string `json:"organization_type"`
	BillingType           string `json:"billing_type"`
	RateLimitTier         string `json:"rate_limit_tier"`
	SubscriptionCreatedAt string `json:"subscription_created_at"`
	SubscriptionStatus    string `json:"subscription_status"`
	HasExtraUsageEnabled  *bool  `json:"has_extra_usage_enabled"`
	HasClaudeMax          *bool  `json:"has_claude_max"`
	HasClaudePro          *bool  `json:"has_claude_pro"`
	// Expire is the timestamp of the token expiry.
	Expire string `json:"expired"`
}

// ClaudeAuthBundle aggregates authentication data after OAuth flow completion
type ClaudeAuthBundle struct {
	// APIKey is the Anthropic API key obtained from token exchange.
	APIKey string `json:"api_key"`
	// TokenData contains the OAuth tokens from the authentication flow.
	TokenData ClaudeTokenData `json:"token_data"`
	// DeviceIDs contains the single device identity persisted with this credential.
	DeviceIDs []string `json:"claude_device_ids"`
	// LastRefresh is the timestamp of the last token refresh.
	LastRefresh string `json:"last_refresh"`
}
