package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v5"

	"ztatic-go-framework/data"
	"ztatic-go-framework/internal/auth"
	"ztatic-go-framework/realtime"
)

func TestSSE_AuthenticationAndTopicAuthorization(t *testing.T) {
	e := echo.New()
	dbEngine, err := data.NewDBEngine("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create memory DB: %v", err)
	}
	defer dbEngine.Close()

	broker := realtime.NewMemoryBroker()
	sseAuthorizer := func(c *echo.Context, topic string) bool {
		userID := auth.GetUserID(c)
		if strings.HasPrefix(topic, "nest:user_") {
			return topic == fmt.Sprintf("nest:user_%d", userID)
		}
		return true
	}
	e.GET("/sse", realtime.AuthorizedSSEHandler(broker, sseAuthorizer), auth.RequireAuth(dbEngine))

	// 1. Unauthenticated request from remote IP must return 401 Unauthorized
	reqUnauth := httptest.NewRequest(http.MethodGet, "/sse?topic=nest:user_1", nil)
	reqUnauth.RemoteAddr = "192.168.1.50:4321"
	reqUnauth.Header.Set("X-Forwarded-For", "192.168.1.50")
	recUnauth := httptest.NewRecorder()
	e.ServeHTTP(recUnauth, reqUnauth)
	if recUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized for unauthenticated remote SSE request, got %d", recUnauth.Code)
	}

	// 2. Authenticated user 1 subscribing to user 2's topic must return 403 Forbidden
	sessUser1 := auth.CreateUserSession(1)
	reqForbidden := httptest.NewRequest(http.MethodGet, "/sse?topic=nest:user_2", nil)
	reqForbidden.RemoteAddr = "192.168.1.50:4321"
	reqForbidden.Header.Set("X-Forwarded-For", "192.168.1.50")
	reqForbidden.Header.Set("Authorization", "Bearer "+sessUser1)
	recForbidden := httptest.NewRecorder()
	e.ServeHTTP(recForbidden, reqForbidden)
	if recForbidden.Code != http.StatusForbidden {
		t.Fatalf("Expected 403 Forbidden when user 1 subscribes to user 2's topic, got %d", recForbidden.Code)
	}

	// 3. Authenticated user 1 subscribing to user 1's topic must succeed with text/event-stream
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reqAllowed := httptest.NewRequest(http.MethodGet, "/sse?topic=nest:user_1", nil).WithContext(ctx)
	reqAllowed.RemoteAddr = "192.168.1.50:4321"
	reqAllowed.Header.Set("X-Forwarded-For", "192.168.1.50")
	reqAllowed.Header.Set("Authorization", "Bearer "+sessUser1)
	recAllowed := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		e.ServeHTTP(recAllowed, reqAllowed)
		close(done)
	}()

	time.Sleep(30 * time.Millisecond)
	cancel()
	<-done

	if recAllowed.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatalf("Expected Content-Type text/event-stream for authorized SSE connection, got %q", recAllowed.Header().Get("Content-Type"))
	}
	if recAllowed.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("Expected Cache-Control no-cache, got %q", recAllowed.Header().Get("Cache-Control"))
	}

	// 4. Missing topic parameter returns 400 Bad Request
	reqMissingTopic := httptest.NewRequest(http.MethodGet, "/sse", nil)
	reqMissingTopic.RemoteAddr = "192.168.1.50:4321"
	reqMissingTopic.Header.Set("X-Forwarded-For", "192.168.1.50")
	reqMissingTopic.Header.Set("Authorization", "Bearer "+sessUser1)
	recMissingTopic := httptest.NewRecorder()
	e.ServeHTTP(recMissingTopic, reqMissingTopic)
	if recMissingTopic.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 Bad Request for missing topic, got %d", recMissingTopic.Code)
	}
}
