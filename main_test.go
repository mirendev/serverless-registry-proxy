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

func TestParseImageAliases(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want map[string]string
	}{
		{"empty", "", nil},
		{"only spaces and commas", " , ,, ", nil},
		{"invalid format ignored", "bun,valkey:valkey/valkey", map[string]string{"valkey": "valkey/valkey"}},
		{"empty key or value ignored", "bun:, :valkey/valkey, valkey:valkey/valkey", map[string]string{"valkey": "valkey/valkey"}},
		{"single alias", "bun:oven/bun", map[string]string{"bun": "oven/bun"}},
		{"multiple aliases with spaces", "bun:oven/bun , valkey:valkey/valkey", map[string]string{"bun": "oven/bun", "valkey": "valkey/valkey"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseImageAliases(tc.raw)
			if len(tc.want) == 0 {
				if got != nil {
					t.Fatalf("expected nil map, got %v", got)
				}
				return
			}
			if len(got) != len(tc.want) {
				t.Fatalf("expected %d entries, got %d (%v)", len(tc.want), len(got), got)
			}
			for k, v := range tc.want {
				if gotVal, ok := got[k]; !ok || gotVal != v {
					t.Errorf("expected %s -> %s, got %s in map %v", k, v, gotVal, got)
				}
			}
		})
	}
}

func TestRewriteAlias(t *testing.T) {
	aliases := map[string]string{
		"bun":    "oven/bun",
		"valkey": "valkey/valkey",
	}
	cases := []struct {
		path string
		want string
	}{
		{"/v2/", "/v2/"},
		{"/v2/ruby/manifests/latest", "/v2/ruby/manifests/latest"}, // no alias
		{"/v2/bun/manifests/latest", "/v2/oven/bun/manifests/latest"},
		{"/v2/bun/manifests/v1", "/v2/bun/manifests/v1"}, // legacy tag v1 bypasses alias
		{"/v2/bun/manifests/v2", "/v2/bun/manifests/v2"}, // legacy tag v2 bypasses alias
		{"/v2/bun/blobs/sha256:abc", "/v2/oven/bun/blobs/sha256:abc"},
		{"/v2/valkey/tags/list", "/v2/valkey/valkey/tags/list"},
		{"/v2/bun", "/v2/oven/bun"},
		{"/_token", "/_token"},
		{"/", "/"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			if got := rewriteAlias(tc.path, aliases); got != tc.want {
				t.Errorf("rewriteAlias(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

func TestRewriteScopeAlias(t *testing.T) {
	aliases := map[string]string{
		"bun":    "oven/bun",
		"valkey": "valkey/valkey",
	}
	cases := []struct {
		scope string
		want  string
	}{
		{"", ""},
		{"invalid_scope", "invalid_scope"},
		{"repository:ruby:pull", "repository:ruby:pull"},
		{"repository:bun:pull", "repository:oven/bun:pull"},
		{"repository:valkey:pull,push", "repository:valkey/valkey:pull,push"},
		{"repository:bun/extra:pull", "repository:oven/bun/extra:pull"},
	}
	for _, tc := range cases {
		t.Run(tc.scope, func(t *testing.T) {
			if got := rewriteScopeAlias(tc.scope, aliases); got != tc.want {
				t.Errorf("rewriteScopeAlias(%q) = %q, want %q", tc.scope, got, tc.want)
			}
		})
	}
}

func TestResolveRepositoryPath(t *testing.T) {
	repoPrefix := "miren-cloud/miren-oci-virtual"
	cases := []struct {
		name string
		path string
		want string
	}{
		{"empty path", "", ""},
		{"v2 root", "/v2/", "/v2/"},
		{"standard image", "/v2/oven/bun/manifests/latest", "/v2/miren-cloud/miren-oci-virtual/oven/bun/manifests/latest"},
		{"explicit remote image", "/v2/ghcr-remote/mirendev/buildkit/manifests/latest", "/v2/miren-cloud/ghcr-remote/mirendev/buildkit/manifests/latest"},
		{"explicit k8s remote image", "/v2/k8s-remote/pause/manifests/latest", "/v2/miren-cloud/k8s-remote/pause/manifests/latest"},
		{"already resolved path", "/v2/miren-cloud/miren-oci-virtual/oven/bun/manifests/latest", "/v2/miren-cloud/miren-oci-virtual/oven/bun/manifests/latest"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveRepositoryPath(repoPrefix, tc.path); got != tc.want {
				t.Errorf("resolveRepositoryPath(%q, %q) = %q, want %q", repoPrefix, tc.path, got, tc.want)
			}
		})
	}
}

func TestResolveScopePath(t *testing.T) {
	repoPrefix := "miren-cloud/miren-oci-virtual"
	cases := []struct {
		name  string
		scope string
		want  string
	}{
		{"empty scope", "", ""},
		{"invalid prefix", "something:else", "something:else"},
		{"standard repository scope", "repository:oven/bun:pull", "repository:miren-cloud/miren-oci-virtual/oven/bun:pull"},
		{"remote repository scope", "repository:ghcr-remote/mirendev/buildkit:pull", "repository:miren-cloud/ghcr-remote/mirendev/buildkit:pull"},
		{"k8s remote repository scope", "repository:k8s-remote/pause:pull,push", "repository:miren-cloud/k8s-remote/pause:pull,push"},
		{"already resolved scope", "repository:miren-cloud/miren-oci-virtual/oven/bun:pull", "repository:miren-cloud/miren-oci-virtual/oven/bun:pull"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveScopePath(repoPrefix, tc.scope); got != tc.want {
				t.Errorf("resolveScopePath(%q, %q) = %q, want %q", repoPrefix, tc.scope, got, tc.want)
			}
		})
	}
}

