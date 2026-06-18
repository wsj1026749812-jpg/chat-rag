package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/zgsm-ai/chat-rag/internal/client"
	"github.com/zgsm-ai/chat-rag/internal/config"
	"github.com/zgsm-ai/chat-rag/internal/logger"
	"go.uber.org/zap"
)

// NewTokenAuthService exchanges an email address for the token required by the inner gateway.
type NewTokenAuthService struct {
	cfg        config.NewTokenAuthConfig
	redis      client.RedisInterface
	httpClient *http.Client
}

func NewNewTokenAuthService(cfg config.NewTokenAuthConfig, redisClient client.RedisInterface) *NewTokenAuthService {
	timeout := time.Duration(cfg.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	return &NewTokenAuthService{
		cfg:   cfg,
		redis: redisClient,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

func (s *NewTokenAuthService) Enabled() bool {
	return s != nil && s.cfg.Enabled
}

func (s *NewTokenAuthService) Authorization(ctx context.Context, email string) (string, error) {
	if s == nil || !s.cfg.Enabled {
		return "", nil
	}
	if s.cfg.FixedEmail != "" {
		email = s.cfg.FixedEmail
	}
	email = strings.TrimSpace(email)
	if email == "" {
		return "", fmt.Errorf("new token auth email is empty")
	}

	token, err := s.getCachedToken(ctx, email)
	if err == nil && token != "" {
		return s.formatAuthorization(token), nil
	}

	token, err = s.fetchToken(ctx, email)
	if err != nil {
		return "", err
	}
	if token == "" {
		return "", fmt.Errorf("new token auth response token is empty")
	}

	if err := s.cacheToken(ctx, email, token); err != nil {
		logger.WarnC(ctx, "failed to cache new token", zap.String("email", email), zap.Error(err))
	}

	return s.formatAuthorization(token), nil
}

func (s *NewTokenAuthService) getCachedToken(ctx context.Context, email string) (string, error) {
	if s.redis == nil {
		return "", fmt.Errorf("redis client is nil")
	}
	token, err := s.redis.GetHashField(ctx, s.cfg.CacheKey, email)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(token), nil
}

func (s *NewTokenAuthService) cacheToken(ctx context.Context, email, token string) error {
	if s.redis == nil {
		return fmt.Errorf("redis client is nil")
	}
	ttl := time.Duration(s.cfg.CacheTTLSeconds) * time.Second
	return s.redis.SetHashField(ctx, s.cfg.CacheKey, email, token, ttl)
}

func (s *NewTokenAuthService) fetchToken(ctx context.Context, email string) (string, error) {
	if s.cfg.Endpoint == "" {
		return "", fmt.Errorf("new token auth endpoint is empty")
	}

	body, err := json.Marshal(map[string]string{"key": email})
	if err != nil {
		return "", fmt.Errorf("failed to marshal new token auth request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create new token auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if s.cfg.OpenToken != "" {
		req.Header.Set(s.cfg.HeaderName, s.cfg.OpenToken)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to request new token auth endpoint: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read new token auth response: %w", err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("new token auth endpoint returned status %d: %s", resp.StatusCode, string(respBody))
	}

	token := extractTokenFromBody(respBody)
	if token == "" {
		logger.WarnC(ctx, "new token auth response did not match known token fields",
			zap.String("body", string(respBody)))
	}
	return token, nil
}

func (s *NewTokenAuthService) formatAuthorization(token string) string {
	token = strings.TrimSpace(token)
	if token == "" || s.cfg.AuthScheme == "" {
		return token
	}
	if strings.Contains(token, " ") {
		return token
	}
	return s.cfg.AuthScheme + " " + token
}

func extractTokenFromBody(body []byte) string {
	plain := strings.TrimSpace(string(body))
	if plain == "" {
		return ""
	}

	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return strings.Trim(plain, `"`)
	}
	return findToken(raw)
}

func findToken(value any) string {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case map[string]any:
		for _, key := range []string{"key", "token", "newToken", "new_token", "openToken", "open_token", "accessToken", "access_token", "authorization", "Authorization"} {
			if token, ok := v[key].(string); ok && strings.TrimSpace(token) != "" {
				return strings.TrimSpace(token)
			}
		}
		for _, key := range []string{"data", "result"} {
			if nested, ok := v[key]; ok {
				if token := findToken(nested); token != "" {
					return token
				}
			}
		}
	}
	return ""
}
