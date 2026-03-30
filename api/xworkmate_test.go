package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"account/internal/auth"
	"account/internal/store"
)

func newXWorkmateTestHarness(t *testing.T) (*gin.Engine, *store.User, string) {
	t.Helper()

	ctx := context.Background()
	st := store.NewMemoryStore()
	user := &store.User{
		Name:          "XWorkmate Admin",
		Email:         "xworkmate-admin@example.com",
		EmailVerified: true,
		Role:          store.RoleAdmin,
		Level:         store.LevelAdmin,
		Active:        true,
	}
	if err := st.CreateUser(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	token := "xworkmate-session-token"
	if err := st.CreateSession(ctx, token, user.ID, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("create session: %v", err)
	}

	router := gin.New()
	RegisterRoutes(
		router,
		WithStore(st),
		WithEmailVerification(false),
		WithTokenService(auth.NewTokenService(auth.TokenConfig{
			PublicToken:   "public-token",
			RefreshSecret: "refresh-secret",
			AccessSecret:  "access-secret",
			AccessExpiry:  time.Hour,
			RefreshExpiry: time.Hour,
			Store:         st,
		})),
	)
	return router, user, token
}

func TestBuildXWorkmateTokenConfiguredUsesSecretLocators(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		profile  *store.XWorkmateProfile
		openclaw bool
		vault    bool
		apisix   bool
	}{
		{
			name: "missing secret key stays false",
			profile: &store.XWorkmateProfile{
				VaultSecretPath: "kv/openclaw",
			},
		},
		{
			name: "legacy path and key mark openclaw configured",
			profile: &store.XWorkmateProfile{
				VaultSecretPath: "kv/openclaw",
				VaultSecretKey:  "token",
			},
			openclaw: true,
		},
		{
			name: "explicit openclaw locator marks openclaw configured",
			profile: &store.XWorkmateProfile{
				SecretLocators: []store.XWorkmateSecretLocator{
					{
						Provider:   "vault",
						SecretPath: "kv/openclaw",
						SecretKey:  "token",
						Target:     store.XWorkmateSecretLocatorTargetOpenclawGatewayToken,
					},
				},
			},
			openclaw: true,
		},
		{
			name: "other locator stays false",
			profile: &store.XWorkmateProfile{
				SecretLocators: []store.XWorkmateSecretLocator{
					{
						Provider:   "vault",
						SecretPath: "kv/ai",
						SecretKey:  "token",
						Target:     store.XWorkmateSecretLocatorTargetAIGatewayAccessToken,
					},
				},
			},
		},
		{
			name:    "blank profile stays false",
			profile: &store.XWorkmateProfile{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := buildXWorkmateTokenConfigured(tt.profile)
			if got := result["openclaw"].(bool); got != tt.openclaw {
				t.Fatalf("expected openclaw=%v, got %v", tt.openclaw, got)
			}
			if got := result["vault"].(bool); got != tt.vault {
				t.Fatalf("expected vault=%v, got %v", tt.vault, got)
			}
			if got := result["apisix"].(bool); got != tt.apisix {
				t.Fatalf("expected apisix=%v, got %v", tt.apisix, got)
			}
		})
	}
}

func TestUpdateAndGetXWorkmateProfileRoundTripsSecretLocators(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router, _, token := newXWorkmateTestHarness(t)
	body, err := json.Marshal(map[string]any{
		"profile": map[string]any{
			"openclawUrl":    "wss://gateway.example.com",
			"openclawOrigin": "https://gateway.example.com",
			"vaultUrl":       "https://vault.example.com",
			"vaultNamespace": "team-a",
			"secretLocators": []map[string]any{
				{
					"id":         "locator-openclaw",
					"provider":   "vault",
					"secretPath": "kv/openclaw",
					"secretKey":  "token",
					"target":     store.XWorkmateSecretLocatorTargetOpenclawGatewayToken,
					"required":   true,
				},
				{
					"id":         "locator-ai-gateway",
					"provider":   "vault",
					"secretPath": "kv/ai",
					"secretKey":  "access-token",
					"target":     store.XWorkmateSecretLocatorTargetAIGatewayAccessToken,
				},
			},
			"apisixUrl": "https://apigw.example.com",
		},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	putReq := httptest.NewRequest(http.MethodPut, "/api/auth/xworkmate/profile", bytes.NewReader(body))
	putReq.Header.Set("Content-Type", "application/json")
	putReq.Header.Set("Authorization", "Bearer "+token)
	putReq.Header.Set("X-Forwarded-Host", store.SharedXWorkmateDomain)
	putRec := httptest.NewRecorder()
	router.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("expected update success, got %d: %s", putRec.Code, putRec.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/auth/xworkmate/profile", nil)
	getReq.Header.Set("Authorization", "Bearer "+token)
	getReq.Header.Set("X-Forwarded-Host", store.SharedXWorkmateDomain)
	getRec := httptest.NewRecorder()
	router.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("expected profile fetch success, got %d: %s", getRec.Code, getRec.Body.String())
	}

	var resp struct {
		Profile struct {
			OpenclawURL    string `json:"openclawUrl"`
			OpenclawOrigin string `json:"openclawOrigin"`
			VaultURL       string `json:"vaultUrl"`
			VaultNamespace string `json:"vaultNamespace"`
			SecretLocators []struct {
				ID         string `json:"id"`
				Provider   string `json:"provider"`
				SecretPath string `json:"secretPath"`
				SecretKey  string `json:"secretKey"`
				Target     string `json:"target"`
				Required   bool   `json:"required"`
			} `json:"secretLocators"`
			VaultSecretPath string `json:"vaultSecretPath"`
			VaultSecretKey  string `json:"vaultSecretKey"`
			ApisixURL       string `json:"apisixUrl"`
		} `json:"profile"`
		TokenConfigured struct {
			Openclaw bool `json:"openclaw"`
			Vault    bool `json:"vault"`
			Apisix   bool `json:"apisix"`
		} `json:"tokenConfigured"`
	}
	if err := json.Unmarshal(getRec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode profile response: %v", err)
	}

	if resp.Profile.VaultSecretPath != "kv/openclaw" || resp.Profile.VaultSecretKey != "token" {
		t.Fatalf("expected compatibility fields to mirror openclaw locator, got %#v", resp.Profile)
	}
	if len(resp.Profile.SecretLocators) != 2 {
		t.Fatalf("expected 2 locators, got %#v", resp.Profile.SecretLocators)
	}
	if resp.Profile.SecretLocators[0].ID != "locator-openclaw" || !resp.Profile.SecretLocators[0].Required {
		t.Fatalf("expected openclaw locator to round-trip, got %#v", resp.Profile.SecretLocators[0])
	}
	if resp.Profile.SecretLocators[0].Target != store.XWorkmateSecretLocatorTargetOpenclawGatewayToken {
		t.Fatalf("expected openclaw target, got %#v", resp.Profile.SecretLocators[0])
	}
	if resp.Profile.SecretLocators[1].Target != store.XWorkmateSecretLocatorTargetAIGatewayAccessToken {
		t.Fatalf("expected ai gateway target, got %#v", resp.Profile.SecretLocators[1])
	}
	if !resp.TokenConfigured.Openclaw {
		t.Fatalf("expected openclaw tokenConfigured=true when locator and key are present")
	}
	if resp.TokenConfigured.Vault {
		t.Fatalf("expected vault tokenConfigured=false without a vault-backed token locator")
	}
	if resp.TokenConfigured.Apisix {
		t.Fatalf("expected apisix tokenConfigured=false without a token locator")
	}
}

func TestUpdateXWorkmateProfileSynthesizesSecretLocatorsFromLegacyFields(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router, _, token := newXWorkmateTestHarness(t)
	body, err := json.Marshal(map[string]any{
		"profile": map[string]any{
			"openclawUrl":     "wss://gateway.example.com",
			"openclawOrigin":  "https://gateway.example.com",
			"vaultUrl":        "https://vault.example.com",
			"vaultNamespace":  "team-a",
			"vaultSecretPath": "kv/openclaw",
			"vaultSecretKey":  "token",
			"apisixUrl":       "https://apigw.example.com",
		},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	putReq := httptest.NewRequest(http.MethodPut, "/api/auth/xworkmate/profile", bytes.NewReader(body))
	putReq.Header.Set("Content-Type", "application/json")
	putReq.Header.Set("Authorization", "Bearer "+token)
	putReq.Header.Set("X-Forwarded-Host", store.SharedXWorkmateDomain)
	putRec := httptest.NewRecorder()
	router.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("expected update success, got %d: %s", putRec.Code, putRec.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/auth/xworkmate/profile", nil)
	getReq.Header.Set("Authorization", "Bearer "+token)
	getReq.Header.Set("X-Forwarded-Host", store.SharedXWorkmateDomain)
	getRec := httptest.NewRecorder()
	router.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("expected profile fetch success, got %d: %s", getRec.Code, getRec.Body.String())
	}

	var resp struct {
		Profile struct {
			SecretLocators []struct {
				Provider   string `json:"provider"`
				SecretPath string `json:"secretPath"`
				SecretKey  string `json:"secretKey"`
				Target     string `json:"target"`
			} `json:"secretLocators"`
			VaultSecretPath string `json:"vaultSecretPath"`
			VaultSecretKey  string `json:"vaultSecretKey"`
		} `json:"profile"`
	}
	if err := json.Unmarshal(getRec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode profile response: %v", err)
	}

	if len(resp.Profile.SecretLocators) != 1 {
		t.Fatalf("expected synthesized single locator, got %#v", resp.Profile.SecretLocators)
	}
	if resp.Profile.SecretLocators[0].Provider != "vault" || resp.Profile.SecretLocators[0].Target != store.XWorkmateSecretLocatorTargetOpenclawGatewayToken {
		t.Fatalf("expected synthesized openclaw vault locator, got %#v", resp.Profile.SecretLocators[0])
	}
	if resp.Profile.VaultSecretPath != "kv/openclaw" || resp.Profile.VaultSecretKey != "token" {
		t.Fatalf("expected legacy fields to remain readable, got %#v", resp.Profile)
	}
}

func TestUpdateXWorkmateProfileRejectsNestedRawTokenFields(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router, _, token := newXWorkmateTestHarness(t)

	body, err := json.Marshal(map[string]any{
		"profile": map[string]any{
			"openclawUrl": "wss://gateway.example.com",
			"security": map[string]any{
				"gatewayToken": "secret-value",
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	req := httptest.NewRequest(http.MethodPut, "/api/auth/xworkmate/profile", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Forwarded-Host", store.SharedXWorkmateDomain)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected raw token rejection, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error != "token_persistence_forbidden" {
		t.Fatalf("expected token_persistence_forbidden, got %q", resp.Error)
	}
}
