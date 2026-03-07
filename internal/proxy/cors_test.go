package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCORSMiddlewareNil(t *testing.T) {
	m := NewCORSMiddleware(nil)
	assert.Nil(t, m)

	m = NewCORSMiddleware([]string{})
	assert.Nil(t, m)
}

func TestCORSMiddlewareAllowedOrigin(t *testing.T) {
	m := NewCORSMiddleware([]string{"http://example.com", "http://other.com"})
	handler := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "http://example.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, "http://example.com", rec.Header().Get("Access-Control-Allow-Origin"))
	assert.Contains(t, rec.Header().Get("Access-Control-Allow-Headers"), "Content-Type")
	assert.Contains(t, rec.Header().Get("Access-Control-Expose-Headers"), "X-Request-Id")
	assert.Equal(t, "Origin", rec.Header().Get("Vary"))
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestCORSMiddlewareDisallowedOrigin(t *testing.T) {
	m := NewCORSMiddleware([]string{"http://example.com"})
	handler := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "http://evil.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestCORSMiddlewareWildcard(t *testing.T) {
	m := NewCORSMiddleware([]string{"*"})
	handler := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "http://anything.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, "http://anything.com", rec.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORSMiddlewarePreflight(t *testing.T) {
	m := NewCORSMiddleware([]string{"http://example.com"})
	handler := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called for OPTIONS")
	}))

	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "http://example.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "http://example.com", rec.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORSMiddlewarePreflightDisallowed(t *testing.T) {
	m := NewCORSMiddleware([]string{"http://example.com"})
	nextCalled := false
	handler := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "http://evil.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
	assert.True(t, nextCalled, "next handler should be called for disallowed origin OPTIONS")
}

func TestCORSMiddlewareNoOrigin(t *testing.T) {
	m := NewCORSMiddleware([]string{"http://example.com"})
	handler := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, http.StatusOK, rec.Code)
}
