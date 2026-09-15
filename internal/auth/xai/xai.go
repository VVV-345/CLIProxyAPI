package xai

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"
)

// XAIAuth performs xAI OAuth discovery, device-code login, and refresh.
type XAIAuth struct {
	httpClient *http.Client
}

type tokenResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	IDToken          string `json:"id_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
}

var xaiRefreshGroup singleflight.Group

// NewXAIAuth creates an xAI OAuth helper using config proxy settings.
func NewXAIAuth(cfg *config.Config) *XAIAuth {
	return NewXAIAuthWithProxyURL(cfg, "")
}

// NewXAIAuthWithProxyURL creates an xAI OAuth helper with an explicit proxy URL.
func NewXAIAuthWithProxyURL(cfg *config.Config, proxyURL string) *XAIAuth {
	effectiveProxyURL := strings.TrimSpace(proxyURL)
	var sdkCfg config.SDKConfig
	if cfg != nil {
		sdkCfg = cfg.SDKConfig
		if effectiveProxyURL == "" {
			effectiveProxyURL = strings.TrimSpace(cfg.ProxyURL)
		}
	}
	sdkCfg.ProxyURL = effectiveProxyURL
	return &XAIAuth{httpClient: util.SetProxy(&sdkCfg, &http.Client{Timeout: httpClientTimeout})}
}

// ValidateOAuthEndpoint validates an endpoint returned by xAI discovery.
func ValidateOAuthEndpoint(rawURL string, field string) (string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", fmt.Errorf("xai discovery %s is empty", field)
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("xai discovery %s is invalid: %w", field, err)
	}
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("xai discovery %s must use https: %q", field, rawURL)
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host != "x.ai" && !strings.HasSuffix(host, ".x.ai") {
		return "", fmt.Errorf("xai discovery %s host %q is not on x.ai", field, host)
	}
	return rawURL, nil
}

// Discover resolves xAI OAuth endpoints through OIDC discovery.
func (a *XAIAuth) Discover(ctx context.Context) (*Discovery, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, DiscoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("xai discovery: create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("xai discovery: request failed: %w", err)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("xai discovery: close response body error: %v", errClose)
		}
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("xai discovery: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("xai discovery failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var payload struct {
		DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
		TokenEndpoint               string `json:"token_endpoint"`
		UserInfoEndpoint            string `json:"userinfo_endpoint"`
	}
	if err = json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("xai discovery: parse response: %w", err)
	}
	deviceAuthorizationEndpoint, err := ValidateOAuthEndpoint(payload.DeviceAuthorizationEndpoint, "device_authorization_endpoint")
	if err != nil {
		return nil, err
	}
	tokenEndpoint, err := ValidateOAuthEndpoint(payload.TokenEndpoint, "token_endpoint")
	if err != nil {
		return nil, err
	}
	userInfoEndpoint := ""
	if strings.TrimSpace(payload.UserInfoEndpoint) != "" {
		userInfoEndpoint, err = ValidateOAuthEndpoint(payload.UserInfoEndpoint, "userinfo_endpoint")
		if err != nil {
			return nil, err
		}
	}
	return &Discovery{
		DeviceAuthorizationEndpoint: deviceAuthorizationEndpoint,
		TokenEndpoint:               tokenEndpoint,
		UserInfoEndpoint:            userInfoEndpoint,
	}, nil
}

// StartDeviceFlow requests a device code from xAI.
func (a *XAIAuth) StartDeviceFlow(ctx context.Context) (*DeviceCodeResponse, error) {
	discovery, errDiscover := a.Discover(ctx)
	if errDiscover != nil {
		return nil, errDiscover
	}
	deviceCode, errRequest := a.RequestDeviceCode(ctx, discovery.DeviceAuthorizationEndpoint, discovery.TokenEndpoint)
	if errRequest != nil {
		return nil, errRequest
	}
	deviceCode.UserInfoEndpoint = discovery.UserInfoEndpoint
	return deviceCode, nil
}

// RequestDeviceCode requests a device authorization code from the given endpoint.
func (a *XAIAuth) RequestDeviceCode(ctx context.Context, deviceAuthorizationEndpoint, tokenEndpoint string) (*DeviceCodeResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	deviceAuthorizationEndpoint = strings.TrimSpace(deviceAuthorizationEndpoint)
	if deviceAuthorizationEndpoint == "" {
		return nil, fmt.Errorf("xai device code: device authorization endpoint is required")
	}

	form := url.Values{
		"client_id": {ClientID},
		"scope":     {Scope},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, deviceAuthorizationEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("xai device code: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("xai device code request failed: %w", err)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("xai device code: close response body error: %v", errClose)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("xai device code: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("xai device code request failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var deviceCode DeviceCodeResponse
	if err = json.Unmarshal(body, &deviceCode); err != nil {
		return nil, fmt.Errorf("xai device code: parse response: %w", err)
	}
	if strings.TrimSpace(deviceCode.DeviceCode) == "" {
		return nil, fmt.Errorf("xai device code: response missing device_code")
	}
	if strings.TrimSpace(deviceCode.UserCode) == "" {
		return nil, fmt.Errorf("xai device code: response missing user_code")
	}
	if strings.TrimSpace(deviceCode.VerificationURI) == "" && strings.TrimSpace(deviceCode.VerificationURIComplete) == "" {
		return nil, fmt.Errorf("xai device code: response missing verification URI")
	}
	deviceCode.TokenEndpoint = strings.TrimSpace(tokenEndpoint)
	return &deviceCode, nil
}

// WaitForAuthorization polls until the user authorizes the device code and returns tokens.
func (a *XAIAuth) WaitForAuthorization(ctx context.Context, deviceCode *DeviceCodeResponse) (*AuthBundle, error) {
	tokenData, err := a.PollForToken(ctx, deviceCode)
	if err != nil {
		return nil, err
	}
	tokenEndpoint := ""
	if deviceCode != nil {
		tokenEndpoint = strings.TrimSpace(deviceCode.TokenEndpoint)
	}
	if errIdentity := a.HydrateIdentity(ctx, tokenData, deviceCode.UserInfoEndpoint); errIdentity != nil {
		log.WithError(errIdentity).Debug("xai userinfo request failed")
	}
	return &AuthBundle{
		TokenData:        *tokenData,
		LastRefresh:      time.Now().UTC().Format(time.RFC3339),
		BaseURL:          DefaultAPIBaseURL,
		TokenEndpoint:    tokenEndpoint,
		UserInfoEndpoint: strings.TrimSpace(deviceCode.UserInfoEndpoint),
	}, nil
}

// PollForToken polls the token endpoint until the user authorizes or the device code expires.
func (a *XAIAuth) PollForToken(ctx context.Context, deviceCode *DeviceCodeResponse) (*TokenData, error) {
	if deviceCode == nil {
		return nil, fmt.Errorf("xai device code: response is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	tokenEndpoint := strings.TrimSpace(deviceCode.TokenEndpoint)
	if tokenEndpoint == "" {
		discovery, errDiscover := a.Discover(ctx)
		if errDiscover != nil {
			return nil, errDiscover
		}
		tokenEndpoint = discovery.TokenEndpoint
	}

	interval := time.Duration(deviceCode.Interval) * time.Second
	if interval < defaultPollInterval {
		interval = defaultPollInterval
	}

	deadline := time.Now().Add(MaxPollDuration)
	if deviceCode.ExpiresIn > 0 {
		codeDeadline := time.Now().Add(time.Duration(deviceCode.ExpiresIn) * time.Second)
		if codeDeadline.Before(deadline) {
			deadline = codeDeadline
		}
	}

	// Poll immediately once, then wait between subsequent attempts.
	firstAttempt := true
	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("xai device code: context cancelled: %w", ctx.Err())
		case <-timer.C:
			if !firstAttempt && time.Now().After(deadline) {
				return nil, fmt.Errorf("xai device code expired")
			}
			firstAttempt = false

			token, pollErr, nextInterval, shouldContinue := a.exchangeDeviceCode(ctx, tokenEndpoint, deviceCode.DeviceCode, interval)
			if token != nil {
				return token, nil
			}
			if !shouldContinue {
				return nil, pollErr
			}
			interval = nextInterval
			timer.Reset(interval)
		}
	}
}

// exchangeDeviceCode attempts to exchange a device code for tokens.
// Returns (token, error, nextInterval, shouldContinue).
func (a *XAIAuth) exchangeDeviceCode(ctx context.Context, tokenEndpoint, deviceCode string, interval time.Duration) (*TokenData, error, time.Duration, bool) {
	form := url.Values{
		"grant_type":  {DeviceCodeGrantType},
		"device_code": {strings.TrimSpace(deviceCode)},
		"client_id":   {ClientID},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(tokenEndpoint), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("xai device token: create request: %w", err), interval, false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("xai device token request failed: %w", err), interval, false
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("xai device token: close response body error: %v", errClose)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("xai device token: read response: %w", err), interval, false
	}

	var payload tokenResponse
	if err = json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("xai device token: parse response: %w", err), interval, false
	}

	if payload.Error != "" {
		switch payload.Error {
		case "authorization_pending":
			return nil, nil, interval, true
		case "slow_down":
			nextInterval := interval + defaultPollInterval
			return nil, nil, nextInterval, true
		case "expired_token":
			return nil, fmt.Errorf("xai device code expired"), interval, false
		case "access_denied":
			return nil, fmt.Errorf("xai device authorization denied"), interval, false
		default:
			desc := strings.TrimSpace(payload.ErrorDescription)
			if desc != "" {
				return nil, fmt.Errorf("xai device token error: %s: %s", payload.Error, desc), interval, false
			}
			return nil, fmt.Errorf("xai device token error: %s", payload.Error), interval, false
		}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("xai device token request failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(body))), interval, false
	}
	if strings.TrimSpace(payload.AccessToken) == "" {
		return nil, fmt.Errorf("xai device token response missing access_token"), interval, false
	}

	return buildTokenDataFromResponse(payload), nil, interval, false
}

// RefreshTokens refreshes an xAI access token.
func (a *XAIAuth) RefreshTokens(ctx context.Context, refreshToken, tokenEndpoint string) (*TokenData, error) {
	if strings.TrimSpace(refreshToken) == "" {
		return nil, fmt.Errorf("xai token refresh: refresh token is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	refreshToken = strings.TrimSpace(refreshToken)
	if strings.TrimSpace(tokenEndpoint) == "" {
		discovery, errDiscover := a.Discover(ctx)
		if errDiscover != nil {
			return nil, errDiscover
		}
		tokenEndpoint = discovery.TokenEndpoint
	}
	tokenEndpoint = strings.TrimSpace(tokenEndpoint)

	result, err, _ := xaiRefreshGroup.Do(refreshToken, func() (interface{}, error) {
		return a.refreshTokensSingleFlight(context.WithoutCancel(ctx), refreshToken, tokenEndpoint)
	})
	if err != nil {
		return nil, err
	}
	tokenData, ok := result.(*TokenData)
	if !ok || tokenData == nil {
		return nil, fmt.Errorf("xai token refresh failed: invalid single-flight result")
	}
	return tokenData, nil
}

func (a *XAIAuth) refreshTokensSingleFlight(ctx context.Context, refreshToken, tokenEndpoint string) (*TokenData, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {ClientID},
		"refresh_token": {refreshToken},
	}
	return a.postTokenForm(ctx, tokenEndpoint, form)
}

func (a *XAIAuth) postTokenForm(ctx context.Context, tokenEndpoint string, form url.Values) (*TokenData, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(tokenEndpoint), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("xai token request: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("xai token request failed: %w", err)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("xai token request: close response body error: %v", errClose)
		}
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("xai token response: read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("xai token request failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var payload tokenResponse
	if err = json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("xai token response: parse body: %w", err)
	}
	if strings.TrimSpace(payload.AccessToken) == "" {
		return nil, fmt.Errorf("xai token response missing access_token")
	}
	return buildTokenDataFromResponse(payload), nil
}

// HydrateIdentity merges access-token claims, ID-token claims, and OIDC userinfo.
func (a *XAIAuth) HydrateIdentity(ctx context.Context, tokenData *TokenData, userInfoEndpoint string) error {
	if tokenData == nil {
		return nil
	}
	claims := mergeClaims(parseJWTClaims(tokenData.AccessToken), parseJWTClaims(tokenData.IDToken))
	endpoint := strings.TrimSpace(userInfoEndpoint)
	if endpoint != "" && strings.TrimSpace(tokenData.AccessToken) != "" {
		validatedEndpoint, errValidate := ValidateOAuthEndpoint(endpoint, "userinfo_endpoint")
		if errValidate != nil {
			return errValidate
		}
		req, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, validatedEndpoint, nil)
		if errRequest != nil {
			return fmt.Errorf("xai userinfo: create request: %w", errRequest)
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(tokenData.AccessToken))
		req.Header.Set("Accept", "application/json")
		resp, errDo := a.httpClient.Do(req)
		if errDo != nil {
			return fmt.Errorf("xai userinfo request failed: %w", errDo)
		}
		defer func() {
			if errClose := resp.Body.Close(); errClose != nil {
				log.Errorf("xai userinfo: close response body error: %v", errClose)
			}
		}()
		body, errRead := io.ReadAll(resp.Body)
		if errRead != nil {
			return fmt.Errorf("xai userinfo: read response: %w", errRead)
		}
		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			return fmt.Errorf("xai userinfo request failed with status %d", resp.StatusCode)
		}
		var userInfo map[string]any
		if errUnmarshal := json.Unmarshal(body, &userInfo); errUnmarshal != nil {
			return fmt.Errorf("xai userinfo: parse response: %w", errUnmarshal)
		}
		claims = mergeClaims(claims, userInfo)
	}
	applyIdentityClaims(tokenData, claims)
	return nil
}

// CreateTokenStorage converts an auth bundle into persistable storage.
func (a *XAIAuth) CreateTokenStorage(bundle *AuthBundle) *TokenStorage {
	if bundle == nil {
		return nil
	}
	return &TokenStorage{
		Type:                      "xai",
		AccessToken:               bundle.TokenData.AccessToken,
		RefreshToken:              bundle.TokenData.RefreshToken,
		IDToken:                   bundle.TokenData.IDToken,
		TokenType:                 bundle.TokenData.TokenType,
		ExpiresIn:                 bundle.TokenData.ExpiresIn,
		Expire:                    bundle.TokenData.Expire,
		LastRefresh:               bundle.LastRefresh,
		Email:                     strings.TrimSpace(bundle.TokenData.Email),
		Subject:                   bundle.TokenData.Subject,
		FirstName:                 bundle.TokenData.FirstName,
		LastName:                  bundle.TokenData.LastName,
		UserID:                    bundle.TokenData.UserID,
		PrincipalID:               bundle.TokenData.PrincipalID,
		PrincipalType:             bundle.TokenData.PrincipalType,
		TeamID:                    bundle.TokenData.TeamID,
		ProfileImageAssetID:       bundle.TokenData.ProfileImageAssetID,
		CodingDataRetentionOptOut: bundle.TokenData.CodingDataRetentionOptOut,
		BaseURL:                   firstNonEmpty(bundle.BaseURL, DefaultAPIBaseURL),
		RedirectURI:               bundle.RedirectURI,
		TokenEndpoint:             bundle.TokenEndpoint,
		UserInfoEndpoint:          bundle.UserInfoEndpoint,
		AuthKind:                  "oauth",
	}
}

func buildTokenData(accessToken, refreshToken, idToken, tokenType string, expiresIn int, email, subject string) *TokenData {
	tokenData := &TokenData{
		AccessToken:  strings.TrimSpace(accessToken),
		RefreshToken: strings.TrimSpace(refreshToken),
		IDToken:      strings.TrimSpace(idToken),
		TokenType:    strings.TrimSpace(tokenType),
		ExpiresIn:    expiresIn,
		Email:        email,
		Subject:      subject,
	}
	if expiresIn > 0 {
		tokenData.Expire = time.Now().Add(time.Duration(expiresIn) * time.Second).UTC().Format(time.RFC3339)
	}
	return tokenData
}

func buildTokenDataFromResponse(payload tokenResponse) *TokenData {
	tokenData := buildTokenData(payload.AccessToken, payload.RefreshToken, payload.IDToken, payload.TokenType, payload.ExpiresIn, "", "")
	applyIdentityClaims(tokenData, mergeClaims(parseJWTClaims(payload.AccessToken), parseJWTClaims(payload.IDToken)))
	return tokenData
}

func parseJWTIdentity(token string) (email string, subject string) {
	claims := parseJWTClaims(token)
	return claimString(claims, "email", "preferred_username"), claimString(claims, "sub")
}

func parseJWTClaims(token string) map[string]any {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) < 2 {
		return nil
	}
	payload := parts[1]
	payload += strings.Repeat("=", (4-len(payload)%4)%4)
	raw, errDecode := base64.URLEncoding.DecodeString(payload)
	if errDecode != nil {
		return nil
	}
	var claims map[string]any
	if errUnmarshal := json.Unmarshal(raw, &claims); errUnmarshal != nil {
		return nil
	}
	return claims
}

func mergeClaims(fallback, primary map[string]any) map[string]any {
	merged := make(map[string]any, len(fallback)+len(primary))
	for key, value := range fallback {
		merged[key] = value
	}
	for key, value := range primary {
		merged[key] = value
	}
	return merged
}

func claimString(claims map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := claims[key].(string); ok {
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				return trimmed
			}
		}
	}
	return ""
}

func claimBool(claims map[string]any, keys ...string) *bool {
	for _, key := range keys {
		if value, ok := claims[key].(bool); ok {
			result := value
			return &result
		}
	}
	return nil
}

func applyIdentityClaims(tokenData *TokenData, claims map[string]any) {
	if tokenData == nil {
		return
	}
	tokenData.Email = firstNonEmpty(claimString(claims, "email", "preferred_username"), tokenData.Email)
	tokenData.Subject = firstNonEmpty(claimString(claims, "sub"), tokenData.Subject)
	tokenData.FirstName = claimString(claims, "first_name", "given_name")
	tokenData.LastName = claimString(claims, "last_name", "family_name")
	tokenData.PrincipalID = firstNonEmpty(claimString(claims, "principal_id", "sub"), tokenData.Subject)
	tokenData.UserID = firstNonEmpty(claimString(claims, "user_id", "uid"), tokenData.PrincipalID)
	tokenData.PrincipalType = firstNonEmpty(claimString(claims, "principal_type"), "User")
	tokenData.TeamID = claimString(claims, "team_id")
	tokenData.ProfileImageAssetID = claimString(claims, "profile_image_asset_id", "picture")
	tokenData.CodingDataRetentionOptOut = claimBool(claims, "coding_data_retention_opt_out")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
