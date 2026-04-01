package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"account/internal/agentserver"
	"account/internal/store"
)

func TestAgentUsersUseAccountUUIDAsStatsEmail(t *testing.T) {
	gin.SetMode(gin.TestMode)

	st := store.NewMemoryStore()
	ctx := context.Background()

	if err := st.CreateUser(ctx, &store.User{
		Name:          "Stats User",
		Email:         "stats@example.com",
		PasswordHash:  "hashed",
		EmailVerified: true,
		Role:          store.RoleUser,
		Level:         store.LevelUser,
		Active:        true,
		ProxyUUID:     "proxy-user-id",
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	user, err := st.GetUserByEmail(ctx, "stats@example.com")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}

	registry, err := agentserver.NewRegistry(agentserver.Config{
		Credentials: []agentserver.Credential{{
			ID:    "*",
			Name:  "test-agent",
			Token: "agent-token",
		}},
	})
	if err != nil {
		t.Fatalf("new registry: %v", err)
	}

	router := gin.New()
	RegisterRoutes(router, WithStore(st), WithAgentRegistry(registry), WithEmailVerification(false))

	req := httptest.NewRequest(http.MethodGet, "/api/agent-server/v1/users", nil)
	req.Header.Set("Authorization", "Bearer agent-token")
	req.Header.Set("X-Agent-ID", "hk-xhttp.svc.plus")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rec.Code, rec.Body.String())
	}

	var payload struct {
		Clients []struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"clients"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	for _, client := range payload.Clients {
		if client.Email == user.ID {
			return
		}
	}

	t.Fatalf("expected stats email %q in payload, got %#v", user.ID, payload.Clients)
}

func TestAccountUsageAndPolicyEndpoints(t *testing.T) {
	gin.SetMode(gin.TestMode)

	st := store.NewMemoryStore()
	ctx := context.Background()

	if err := st.CreateUser(ctx, &store.User{
		Name:          "Billing User",
		Email:         "billing@example.com",
		PasswordHash:  "hashed",
		EmailVerified: true,
		Role:          store.RoleUser,
		Level:         store.LevelUser,
		Active:        true,
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	user, err := st.GetUserByEmail(ctx, "billing@example.com")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}

	sessionToken := "usage-session-token"
	if err := st.CreateSession(ctx, sessionToken, user.ID, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatalf("create session: %v", err)
	}

	bucketStart := time.Date(2026, 4, 1, 10, 30, 0, 0, time.UTC)
	if err := st.UpsertTrafficMinuteBucket(ctx, &store.TrafficMinuteBucket{
		BucketStart:   bucketStart,
		NodeID:        "node-a",
		AccountUUID:   user.ID,
		Region:        "hk",
		LineCode:      "premium",
		UplinkBytes:   128,
		DownlinkBytes: 256,
		TotalBytes:    384,
		Multiplier:    1.5,
		RatingStatus:  store.RatingStatusRated,
	}); err != nil {
		t.Fatalf("upsert bucket: %v", err)
	}

	if err := st.UpsertAccountQuotaState(ctx, &store.AccountQuotaState{
		AccountUUID:            user.ID,
		RemainingIncludedQuota: 2048,
		CurrentBalance:         87.5,
		Arrears:                false,
		ThrottleState:          "normal",
		SuspendState:           "active",
		EffectiveAt:            time.Now().UTC(),
	}); err != nil {
		t.Fatalf("upsert quota state: %v", err)
	}

	if err := st.UpsertAccountPolicySnapshot(ctx, &store.AccountPolicySnapshot{
		AccountUUID:        user.ID,
		PolicyVersion:      "policy-v1",
		AuthState:          "active",
		RateProfile:        "standard",
		ConnProfile:        "standard",
		EligibleNodeGroups: []string{"hk-premium"},
		PreferredStrategy:  "ewma",
		DegradeMode:        "fallback",
		ExpiresAt:          time.Now().UTC().Add(5 * time.Minute),
	}); err != nil {
		t.Fatalf("upsert policy: %v", err)
	}

	router := gin.New()
	RegisterRoutes(router, WithStore(st), WithEmailVerification(false))

	req := httptest.NewRequest(http.MethodGet, "/api/account/usage/summary", nil)
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("usage summary status: %d body=%s", rec.Code, rec.Body.String())
	}

	var usagePayload struct {
		AccountUUID string `json:"accountUuid"`
		TotalBytes  int64  `json:"totalBytes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &usagePayload); err != nil {
		t.Fatalf("decode usage payload: %v", err)
	}
	if usagePayload.AccountUUID != user.ID {
		t.Fatalf("expected account uuid %q, got %q", user.ID, usagePayload.AccountUUID)
	}
	if usagePayload.TotalBytes != 384 {
		t.Fatalf("expected total bytes 384, got %d", usagePayload.TotalBytes)
	}

	policyReq := httptest.NewRequest(http.MethodGet, "/api/account/policy", nil)
	policyReq.Header.Set("Authorization", "Bearer "+sessionToken)
	policyRec := httptest.NewRecorder()
	router.ServeHTTP(policyRec, policyReq)

	if policyRec.Code != http.StatusOK {
		t.Fatalf("policy status: %d body=%s", policyRec.Code, policyRec.Body.String())
	}

	var policyPayload struct {
		AccountUUID        string   `json:"accountUuid"`
		PreferredStrategy  string   `json:"preferredStrategy"`
		EligibleNodeGroups []string `json:"eligibleNodeGroups"`
	}
	if err := json.Unmarshal(policyRec.Body.Bytes(), &policyPayload); err != nil {
		t.Fatalf("decode policy payload: %v", err)
	}
	if policyPayload.AccountUUID != user.ID {
		t.Fatalf("expected policy account uuid %q, got %q", user.ID, policyPayload.AccountUUID)
	}
	if policyPayload.PreferredStrategy != "ewma" {
		t.Fatalf("expected preferred strategy ewma, got %q", policyPayload.PreferredStrategy)
	}
	if len(policyPayload.EligibleNodeGroups) != 1 || policyPayload.EligibleNodeGroups[0] != "hk-premium" {
		t.Fatalf("unexpected eligible node groups %#v", policyPayload.EligibleNodeGroups)
	}
}
