/*
Copyright 2020 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
)

const (
	ctxKeyOriginalHost = myContextKey("original-host")
)

var (
	re                 = regexp.MustCompile(`^/v2/`)
	realm              = regexp.MustCompile(`realm="(.*?)"`)
)

type myContextKey string

type registryConfig struct {
	host       string
	repoPrefix string
	aliases    map[string]string
}

func main() {
	host := os.Getenv("HOST")

	port := os.Getenv("PORT")
	if port == "" {
		log.Fatal("PORT environment variable not specified")
	}
	browserRedirects := os.Getenv("DISABLE_BROWSER_REDIRECTS") == ""

	registryHost := os.Getenv("REGISTRY_HOST")
	if registryHost == "" {
		log.Fatal("REGISTRY_HOST environment variable not specified (example: gcr.io)")
	}
	repoPrefix := os.Getenv("REPO_PREFIX")
	if repoPrefix == "" {
		log.Fatal("REPO_PREFIX environment variable not specified")
	}

	allowedImages := parseAllowedImages(os.Getenv("ALLOWED_IMAGES"))
	if len(allowedImages) == 0 {
		log.Printf("image allowlist disabled (ALLOWED_IMAGES unset or empty): forwarding all images")
	} else {
		names := make([]string, 0, len(allowedImages))
		for name := range allowedImages {
			names = append(names, name)
		}
		sort.Strings(names)
		log.Printf("image allowlist enabled: %s", strings.Join(names, ", "))
	}

	imageAliases := parseImageAliases(os.Getenv("IMAGE_ALIASES"))
	if len(imageAliases) > 0 {
		var pairs []string
		for from, to := range imageAliases {
			pairs = append(pairs, fmt.Sprintf("%s -> %s", from, to))
		}
		sort.Strings(pairs)
		log.Printf("image alias routing enabled: %s", strings.Join(pairs, ", "))
	}

	reg := registryConfig{
		host:       registryHost,
		repoPrefix: repoPrefix,
		aliases:    imageAliases,
	}

	tokenEndpoint, err := discoverTokenService(reg.host)
	if err != nil {
		log.Fatalf("target registry's token endpoint could not be discovered: %+v", err)
	}
	log.Printf("discovered token endpoint for backend registry: %s", tokenEndpoint)

	var auth authenticator
	if basic := os.Getenv("AUTH_HEADER"); basic != "" {
		auth = authHeader(basic)
	} else if gcpKey := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); gcpKey != "" {
		b, err := ioutil.ReadFile(gcpKey)
		if err != nil {
			log.Fatalf("could not read key file from %s: %+v", gcpKey, err)
		}
		log.Printf("using specified service account json key to authenticate proxied requests")
		auth = authHeader("Basic " + base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("_json_key:%s", string(b)))))
	}

	mux := http.NewServeMux()
	if browserRedirects {
		mux.Handle("/", browserRedirectHandler(reg))
	}
	if tokenEndpoint != "" {
		mux.Handle("/_token", tokenProxyHandler(tokenEndpoint, repoPrefix, imageAliases))
	}
	mux.Handle("/v2/", allowlistMiddleware(allowedImages, registryAPIProxy(reg, auth)))

	addr := fmt.Sprintf("%s:%s", host, port)
	handler := captureHostHeader(mux)
	log.Printf("starting to listen on %s", addr)
	if cert, key := os.Getenv("TLS_CERT"), os.Getenv("TLS_KEY"); cert != "" && key != "" {
		err = http.ListenAndServeTLS(addr, cert, key, handler)
	} else {
		err = http.ListenAndServe(addr, handler)
	}
	if err != http.ErrServerClosed {
		log.Fatalf("listen error: %+v", err)
	}

	log.Printf("server shutdown successfully")
}

func discoverTokenService(registryHost string) (string, error) {
	url := fmt.Sprintf("https://%s/v2/", registryHost)
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to query the registry host %s: %+v", registryHost, err)
	}
	hdr := resp.Header.Get("www-authenticate")
	if hdr == "" {
		return "", fmt.Errorf("www-authenticate header not returned from %s, cannot locate token endpoint", url)
	}
	matches := realm.FindStringSubmatch(hdr)
	if len(matches) == 0 {
		return "", fmt.Errorf("cannot locate 'realm' in %s response header www-authenticate: %s", url, hdr)
	}
	return matches[1], nil
}

// captureHostHeader is a middleware to capture Host header in a context key.
func captureHostHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		ctx := context.WithValue(req.Context(), ctxKeyOriginalHost, req.Host)
		req = req.WithContext(ctx)
		next.ServeHTTP(rw, req.WithContext(ctx))
	})
}

// tokenProxyHandler proxies the token requests to the specified token service.
// It adjusts the ?scope= parameter in the query from "repository:foo:..." to
// "repository:repoPrefix/foo:.." and reverse proxies the query to the specified
// tokenEndpoint.
func tokenProxyHandler(tokenEndpoint, repoPrefix string, aliases map[string]string) http.HandlerFunc {
	return (&httputil.ReverseProxy{
		FlushInterval: -1,
		Director: func(r *http.Request) {
			orig := r.URL.String()

			q := r.URL.Query()
			scope := q.Get("scope")
			if scope == "" {
				return
			}
			newScope := rewriteScopeAlias(scope, aliases)
			newScope = resolveScopePath(repoPrefix, newScope)
			q.Set("scope", newScope)
			u, _ := url.Parse(tokenEndpoint)
			u.RawQuery = q.Encode()
			r.URL = u
			log.Printf("tokenProxyHandler: rewrote url:%s into:%s", orig, r.URL)
			r.Host = u.Host
		},
	}).ServeHTTP
}

// browserRedirectHandler redirects a request like example.com/my-image to
// REGISTRY_HOST/my-image, which shows a public UI for browsing the registry.
// This works only on registries that support a web UI when the image name is
// entered into the browser, like GCR (gcr.io/google-containers/busybox).
func browserRedirectHandler(cfg registryConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		url := fmt.Sprintf("https://%s/%s%s", cfg.host, cfg.repoPrefix, r.RequestURI)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	}
}

// parseAllowedImages parses a comma-separated list of image names (as set in
// the ALLOWED_IMAGES env var) into a set. Surrounding spaces are trimmed and
// empty entries are ignored. An empty/unset value yields a nil set, which the
// allowlistMiddleware treats as "allow everything".
func parseAllowedImages(raw string) map[string]struct{} {
	set := make(map[string]struct{})
	for _, name := range strings.Split(raw, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		set[name] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

// parseImageAliases parses a comma-separated list of image alias mappings
// (as set in the IMAGE_ALIASES env var) like "bun:oven/bun,valkey:valkey/valkey"
// into a map of from -> to. Surrounding spaces are trimmed and invalid entries
// are skipped.
func parseImageAliases(raw string) map[string]string {
	if raw == "" {
		return nil
	}
	aliases := make(map[string]string)
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.Split(part, ":")
		if len(kv) != 2 {
			log.Printf("warning: invalid image alias format %q (expected 'from:to')", part)
			continue
		}
		from := strings.TrimSpace(kv[0])
		to := strings.TrimSpace(kv[1])
		if from == "" || to == "" {
			log.Printf("warning: empty image alias key or value in %q", part)
			continue
		}
		aliases[from] = to
	}
	if len(aliases) == 0 {
		return nil
	}
	return aliases
}

// rewriteAlias translates a path like /v2/bun/manifests/... to /v2/oven/bun/manifests/...
// based on the configured aliases map.
func rewriteAlias(path string, aliases map[string]string) string {
	if len(aliases) == 0 {
		return path
	}
	if !strings.HasPrefix(path, "/v2/") || path == "/v2/" {
		return path
	}
	if strings.HasSuffix(path, "/manifests/v1") || strings.HasSuffix(path, "/manifests/v2") {
		return path
	}
	rest := strings.TrimPrefix(path, "/v2/")
	for from, to := range aliases {
		if rest == from {
			return "/v2/" + to
		}
		if strings.HasPrefix(rest, from+"/") {
			return "/v2/" + to + "/" + strings.TrimPrefix(rest, from+"/")
		}
	}
	return path
}

// rewriteScopeAlias translates a scope string like "repository:bun:pull" to "repository:oven/bun:pull"
// based on the configured aliases map.
func rewriteScopeAlias(scope string, aliases map[string]string) string {
	if len(aliases) == 0 {
		return scope
	}
	if !strings.HasPrefix(scope, "repository:") {
		return scope
	}
	parts := strings.SplitN(scope, ":", 3)
	if len(parts) < 2 {
		return scope
	}
	repo := parts[1]
	for from, to := range aliases {
		if repo == from {
			parts[1] = to
			return strings.Join(parts, ":")
		}
		if strings.HasPrefix(repo, from+"/") {
			parts[1] = to + "/" + strings.TrimPrefix(repo, from+"/")
			return strings.Join(parts, ":")
		}
	}
	return scope
}

// resolveRepositoryPath resolves the correct GCP registry repository path, routing
// paths with a "-remote" prefix directly to that repository instead of the default prefix.
func resolveRepositoryPath(repoPrefix, path string) string {
	if !strings.HasPrefix(path, "/v2/") || path == "/v2/" {
		return path
	}
	parts := strings.SplitN(repoPrefix, "/", 2)
	project := parts[0]
	defaultRepo := ""
	if len(parts) > 1 {
		defaultRepo = parts[1]
	}

	rest := strings.TrimPrefix(path, "/v2/")
	if strings.HasPrefix(rest, project+"/") {
		return path
	}
	firstSegment := rest
	if idx := strings.IndexByte(rest, '/'); idx >= 0 {
		firstSegment = rest[:idx]
	}

	if strings.HasSuffix(firstSegment, "-remote") {
		return "/v2/" + project + "/" + rest
	}
	return "/v2/" + project + "/" + defaultRepo + "/" + rest
}

// resolveScopePath resolves the scope for token requests, routing scopes with a
// "-remote" prefix directly to that repository instead of the default prefix.
func resolveScopePath(repoPrefix, scope string) string {
	if !strings.HasPrefix(scope, "repository:") {
		return scope
	}
	parts := strings.SplitN(repoPrefix, "/", 2)
	project := parts[0]
	defaultRepo := ""
	if len(parts) > 1 {
		defaultRepo = parts[1]
	}

	scopeParts := strings.SplitN(scope, ":", 3)
	if len(scopeParts) < 2 {
		return scope
	}
	repo := scopeParts[1]
	if strings.HasPrefix(repo, project+"/") {
		return scope
	}

	rest := repo
	firstSegment := rest
	if idx := strings.IndexByte(rest, '/'); idx >= 0 {
		firstSegment = rest[:idx]
	}

	var finalRepo string
	if strings.HasSuffix(firstSegment, "-remote") {
		finalRepo = project + "/" + rest
	} else {
		finalRepo = project + "/" + defaultRepo + "/" + rest
	}

	scopeParts[1] = finalRepo
	return strings.Join(scopeParts, ":")
}

// imageNameFromPath extracts the image name from a Docker Registry v2 API path
// like /v2/{image}/manifests/latest, returning the first path segment after
// /v2/. It returns "" for the bare /v2/ ping endpoint (which has no image).
func imageNameFromPath(path string) string {
	rest := strings.TrimPrefix(path, "/v2/")
	if rest == "" || rest == path {
		return ""
	}
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return rest[:i]
	}
	return rest
}

// allowlistMiddleware guards the /v2/ registry proxy with an image-name
// allowlist. When the allowlist is empty (nil), all requests pass through
// unchanged. Otherwise any /v2/{image}/... request whose image name is not in
// the allowlist is rejected with 404. The bare /v2/ ping endpoint always
// passes, since it carries no image name.
func allowlistMiddleware(allowed map[string]struct{}, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(allowed) > 0 {
			if image := imageNameFromPath(r.URL.Path); image != "" {
				if _, ok := allowed[image]; !ok {
					log.Printf("rejecting request for disallowed image %q: %s", image, r.URL.Path)
					http.NotFound(w, r)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// registryAPIProxy returns a reverse proxy to the specified registry.
func registryAPIProxy(cfg registryConfig, auth authenticator) http.HandlerFunc {
	return (&httputil.ReverseProxy{
		FlushInterval: -1,
		Director:      rewriteRegistryV2URL(cfg),
		Transport: &registryRoundtripper{
			auth: auth,
		},
	}).ServeHTTP
}

// rewriteRegistryV2URL rewrites request.URL like /v2/* that come into the server
// into https://[GCR_HOST]/v2/[PROJECT_ID]/*. It leaves /v2/ as is.
func rewriteRegistryV2URL(c registryConfig) func(*http.Request) {
	return func(req *http.Request) {
		u := req.URL.String()
		req.Host = c.host
		req.URL.Scheme = "https"
		req.URL.Host = c.host
		if req.URL.Path != "/v2/" {
			req.URL.Path = rewriteAlias(req.URL.Path, c.aliases)
			req.URL.Path = resolveRepositoryPath(c.repoPrefix, req.URL.Path)
		}
		log.Printf("rewrote url: %s into %s", u, req.URL)
	}
}

type registryRoundtripper struct {
	auth authenticator
}

func (rrt *registryRoundtripper) RoundTrip(req *http.Request) (*http.Response, error) {
	log.Printf("request received. url=%s", req.URL)

	if rrt.auth != nil {
		req.Header.Set("Authorization", rrt.auth.AuthHeader())
	}

	origHost := req.Context().Value(ctxKeyOriginalHost).(string)
	if ua := req.Header.Get("user-agent"); ua != "" {
		req.Header.Set("user-agent", "gcr-proxy/0.1 customDomain/"+origHost+" "+ua)
	}

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err == nil {
		log.Printf("request completed (status=%d) url=%s", resp.StatusCode, req.URL)
	} else {
		log.Printf("request failed with error: %+v", err)
		return nil, err
	}

	// Google Artifact Registry sends a "location: /artifacts-downloads/..." URL
	// to download blobs. We don't want these routed to the proxy itself.
	if locHdr := resp.Header.Get("location"); req.Method == http.MethodGet &&
		resp.StatusCode == http.StatusFound && strings.HasPrefix(locHdr, "/") {
		resp.Header.Set("location", req.URL.Scheme+"://"+req.URL.Host+locHdr)
	}

	updateTokenEndpoint(resp, origHost)
	return resp, nil
}

// updateTokenEndpoint modifies the response header like:
//    Www-Authenticate: Bearer realm="https://auth.docker.io/token",service="registry.docker.io"
// to point to the https://host/token endpoint to force using local token
// endpoint proxy.
func updateTokenEndpoint(resp *http.Response, host string) {
	v := resp.Header.Get("www-authenticate")
	if v == "" {
		return
	}
	cur := fmt.Sprintf("https://%s/_token", host)
	resp.Header.Set("www-authenticate", realm.ReplaceAllString(v, fmt.Sprintf(`realm="%s"`, cur)))
}

type authenticator interface {
	AuthHeader() string
}

type authHeader string

func (b authHeader) AuthHeader() string { return string(b) }
