package traefik_jwt_dynamic_redirect

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
)

type Config struct {
	RedirectTemplate string `json:"redirectTemplate,omitempty"`
}

func CreateConfig() *Config {
	return &Config{}
}

type JWTMiddleware struct {
	next     http.Handler
	template string
	name     string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &JWTMiddleware{
		next:     next,
		template: config.RedirectTemplate,
		name:     name,
	}, nil
}

func (m *JWTMiddleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	auth := req.Header.Get("Authorization")

	if auth == "" {
		m.next.ServeHTTP(rw, req)
		return
	}

	token := strings.TrimPrefix(auth, "Bearer ")

	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		m.next.ServeHTTP(rw, req)
		return
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		m.next.ServeHTTP(rw, req)
		return
	}

	var claims map[string]interface{}
	err = json.Unmarshal(payload, &claims)
	if err != nil {
		m.next.ServeHTTP(rw, req)
		return
	}

	redirectURL := m.template

	for k, v := range claims {
		str := ""
		if s, ok := v.(string); ok {
			str = s
		}
		redirectURL = strings.ReplaceAll(redirectURL, "{claim."+k+"}", str)
	}

	redirectURL = strings.ReplaceAll(redirectURL, "{token}", token)

	http.Redirect(rw, req, redirectURL, http.StatusFound)
}