package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseAllowedImages(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string // names expected in the set; nil means empty/disabled
	}{
		{"empty", "", nil},
		{"only spaces and commas", " , ,, ", nil},
		{"single", "ruby", []string{"ruby"}},
		{"multiple with spaces", "ruby, python ,golang", []string{"ruby", "python", "golang"}},
		{"empty entries ignored", "ruby,,node,", []string{"ruby", "node"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseAllowedImages(tc.raw)
			if len(tc.want) == 0 {
				if got != nil {
					t.Fatalf("expected nil set, got %v", got)
				}
				return
			}
			if len(got) != len(tc.want) {
				t.Fatalf("expected %d entries, got %d (%v)", len(tc.want), len(got), got)
			}
			for _, name := range tc.want {
				if _, ok := got[name]; !ok {
					t.Errorf("expected %q in set %v", name, got)
				}
			}
		})
	}
}

func TestImageNameFromPath(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/v2/", ""},
		{"/v2/ruby/manifests/latest", "ruby"},
		{"/v2/ruby/blobs/sha256:abc", "ruby"},
		{"/v2/postgres/tags/list", "postgres"},
		{"/v2/miren", "miren"},
		{"/_token", ""}, // not a /v2/ path
		{"/", ""},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			if got := imageNameFromPath(tc.path); got != tc.want {
				t.Errorf("imageNameFromPath(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

func TestAllowlistMiddleware(t *testing.T) {
	// next records that it was reached and returns 200.
	const reachedStatus = http.StatusOK
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(reachedStatus)
	})

	allowSet := map[string]struct{}{"ruby": {}, "miren": {}}

	cases := []struct {
		name    string
		allowed map[string]struct{}
		path    string
		want    int // expected status code
	}{
		{"allowed image passes", allowSet, "/v2/ruby/manifests/latest", reachedStatus},
		{"second allowed image passes", allowSet, "/v2/miren/tags/list", reachedStatus},
		{"disallowed image 404s", allowSet, "/v2/python/manifests/latest", http.StatusNotFound},
		{"case-sensitive mismatch 404s", allowSet, "/v2/Ruby/manifests/latest", http.StatusNotFound},
		{"v2 root never blocked", allowSet, "/v2/", reachedStatus},
		{"empty allowlist allows all", nil, "/v2/anything/manifests/latest", reachedStatus},
		{"empty allowlist allows v2 root", nil, "/v2/", reachedStatus},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := allowlistMiddleware(tc.allowed, next)
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Errorf("path %q: got status %d, want %d", tc.path, rec.Code, tc.want)
			}
		})
	}
}

// TestTokenRouteNeverBlocked confirms the /_token route is mounted separately
// from the allowlisted /v2/ handler, so the allowlist can never block it. The
// middleware only wraps /v2/, but we assert defensively that a /_token path
// extracts no image name and would pass even if routed through it.
func TestTokenRouteNeverBlocked(t *testing.T) {
	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	})
	h := allowlistMiddleware(map[string]struct{}{"ruby": {}}, next)
	req := httptest.NewRequest(http.MethodGet, "/_token?scope=repository:python:pull", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !reached {
		t.Errorf("/_token request was blocked by allowlist; got status %d", rec.Code)
	}
}
