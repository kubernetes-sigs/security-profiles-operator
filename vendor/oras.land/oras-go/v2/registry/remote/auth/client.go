/*
Copyright The ORAS Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package auth provides authentication for a client to a remote registry.
package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"oras.land/oras-go/v2/registry/remote/internal/errutil"
	"oras.land/oras-go/v2/registry/remote/retry"
)

// ErrBasicCredentialNotFound is returned  when the credential is not found for
// basic auth.
var ErrBasicCredentialNotFound = errors.New("basic credential not found")

// DefaultClient is the default auth-decorated client.
var DefaultClient = &Client{
	Client: retry.DefaultClient,
	Header: http.Header{
		"User-Agent": {"oras-go"},
	},
	Cache: DefaultCache,
}

// maxResponseBytes specifies the default limit on how many response bytes are
// allowed in the server's response from authorization service servers.
// A typical response message from authorization service servers is around 1 to
// 4 KiB. Since the size of a token must be smaller than the HTTP header size
// limit, which is usually 16 KiB. As specified by the distribution, the
// response may contain 2 identical tokens, that is, 16 x 2 = 32 KiB.
// Hence, 128 KiB should be sufficient.
// References: https://distribution.github.io/distribution/spec/auth/token/
var maxResponseBytes int64 = 128 * 1024 // 128 KiB

// defaultMaxRedirects mirrors the limit enforced by net/http when
// http.Client.CheckRedirect is nil. Installing a CheckRedirect replaces that
// default policy, so the CheckRedirect installed by Client.send must enforce
// the limit itself.
const defaultMaxRedirects = 10

// defaultClientID specifies the default client ID used in OAuth2.
// See also ClientID.
var defaultClientID = "oras-go"

// CredentialFunc represents a function that resolves the credential for the
// given registry (i.e. host:port).
//
// [EmptyCredential] is a valid return value and should not be considered as
// an error.
type CredentialFunc func(ctx context.Context, hostport string) (Credential, error)

// StaticCredential specifies static credentials for the given host.
func StaticCredential(registry string, cred Credential) CredentialFunc {
	if registry == "docker.io" {
		// it is expected that traffic targeting "docker.io" will be redirected
		// to "registry-1.docker.io"
		// reference: https://github.com/moby/moby/blob/v24.0.0-beta.2/registry/config.go#L25-L48
		registry = "registry-1.docker.io"
	}
	return func(_ context.Context, hostport string) (Credential, error) {
		if hostport == registry {
			return cred, nil
		}
		return EmptyCredential, nil
	}
}

// Client is an auth-decorated HTTP client.
// Its zero value is a usable client that uses http.DefaultClient with no cache.
type Client struct {
	// Client is the underlying HTTP client used to access the remote
	// server.
	// If nil, http.DefaultClient is used.
	// It is possible to use the default retry client from the package
	// `oras.land/oras-go/v2/registry/remote/retry`. That client is already available
	// in the DefaultClient.
	// It is also possible to use a custom client. For example, github.com/hashicorp/go-retryablehttp
	// is a popular HTTP client that supports retries.
	Client *http.Client

	// Header contains the custom headers to be added to each request.
	Header http.Header

	// Credential specifies the function for resolving the credential for the
	// given registry (i.e. host:port).
	// EmptyCredential is a valid return value and should not be considered as
	// an error.
	// If nil, the credential is always resolved to EmptyCredential.
	Credential CredentialFunc

	// Cache caches credentials for direct accessing the remote registry.
	// If nil, no cache is used.
	Cache Cache

	// ClientID used in fetching OAuth2 token as a required field.
	// If empty, a default client ID is used.
	// Reference: https://distribution.github.io/distribution/spec/auth/oauth/#getting-a-token
	ClientID string

	// ForceAttemptOAuth2 controls whether to follow OAuth2 with password grant
	// instead the distribution spec when authenticating using username and
	// password.
	// References:
	// - https://distribution.github.io/distribution/spec/auth/jwt/
	// - https://distribution.github.io/distribution/spec/auth/oauth/
	ForceAttemptOAuth2 bool

	// BlockedRealmPrefixes is the denylist of address prefixes a bearer realm
	// host must not be, or resolve to. A realm is rejected if any of its
	// addresses falls in a listed prefix.
	//
	// nil uses DefaultBlockedRealmPrefixes (loopback, link-local,
	// unspecified, and cloud metadata). An empty non-nil slice blocks
	// nothing. A non-empty slice is used exactly, without merging defaults.
	// The scheme check and the https-to-http downgrade check always apply.
	// RFC 1918, IPv6 unique-local, and carrier-grade NAT addresses are
	// allowed by default. Strict mode is
	// append(DefaultBlockedRealmPrefixes(), PrivateRealmPrefixes()...).
	BlockedRealmPrefixes []netip.Prefix
}

// client returns an HTTP client used to access the remote registry.
// http.DefaultClient is return if the client is not configured.
func (c *Client) client() *http.Client {
	if c.Client == nil {
		return http.DefaultClient
	}
	return c.Client
}

// send adds headers to the request and sends the request to the remote server.
func (c *Client) send(req *http.Request) (*http.Response, error) {
	return c.sendRedirectSafe(req, false)
}

// sendRedirectSafe adds headers to the request and sends the request to the
// remote server. If refuseCrossOriginBody is set, a redirect that would resend
// the request body to another origin fails instead of being followed.
func (c *Client) sendRedirectSafe(req *http.Request, refuseCrossOriginBody bool) (*http.Response, error) {
	for key, values := range c.Header {
		req.Header[key] = append(req.Header[key], values...)
	}
	// Drop the Authorization header once a redirect chain has left the HTTP
	// origin (scheme, host, or port) of its first request. The standard
	// library only strips sensitive headers when the hostname changes, so a
	// redirect to a different port on the same host would otherwise forward
	// credentials to an unintended endpoint. The check is made against the
	// first request rather than the previous hop: net/http rebuilds the
	// headers of every redirected request from the first request, so a header
	// deleted on one hop is restored on the next. Any caller-provided
	// CheckRedirect is preserved.
	// References:
	//   - https://github.com/oras-project/oras-go/security/advisories/GHSA-vh4v-2xq2-g5cg
	//   - https://github.com/oras-project/oras-go/security/advisories/GHSA-xc97-9f2f-9hrx
	client := c.client()
	clientCopy := *client
	checkRedirect := client.CheckRedirect
	clientCopy.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 0 && leftOrigin(via, req) {
			if refuseCrossOriginBody && req.Body != nil && req.Body != http.NoBody {
				return fmt.Errorf("%s %q: refusing to resend a token request body to another origin", req.Method, req.URL.Redacted())
			}
			req.Header.Del("Authorization")
		}
		if checkRedirect != nil {
			return checkRedirect(req, via)
		}
		if len(via) >= defaultMaxRedirects {
			return fmt.Errorf("stopped after %d redirects", defaultMaxRedirects)
		}
		return nil
	}
	return clientCopy.Do(req)
}

// leftOrigin reports whether the redirect chain via, followed by req, has left
// the HTTP origin of its first request, which is the request the credential
// was attached for. Once the chain leaves that origin it is treated as having
// left for good, even if a later hop returns to it.
func leftOrigin(via []*http.Request, req *http.Request) bool {
	for _, r := range via[1:] {
		if !sameHTTPOrigin(via[0].URL, r.URL) {
			return true
		}
	}
	return !sameHTTPOrigin(via[0].URL, req.URL)
}

// sameHTTPOrigin reports whether a and b share the same HTTP origin, i.e. the
// same scheme and host. Default ports are normalized so that, for example,
// "example.com" and "example.com:443" compare equal over https.
func sameHTTPOrigin(a, b *url.URL) bool {
	if !strings.EqualFold(a.Scheme, b.Scheme) {
		return false
	}
	return canonicalHost(a) == canonicalHost(b)
}

// isHTTPSUpgrade reports whether a redirect upgrades the same host from
// standard HTTP to standard HTTPS.
func isHTTPSUpgrade(from, to *url.URL) bool {
	return from.Scheme == "http" && to.Scheme == "https" &&
		strings.EqualFold(from.Hostname(), to.Hostname()) &&
		(from.Port() == "" || from.Port() == "80") &&
		(to.Port() == "" || to.Port() == "443")
}

// safeHTTPSUpgrade checks every redirect hop before accepting an upgraded challenge.
func safeHTTPSUpgrade(original, last *http.Request) bool {
	if !isHTTPSUpgrade(original.URL, last.URL) {
		return false
	}
	if original.Host != "" && !strings.EqualFold(original.Host, original.URL.Host) {
		return false
	}
	for req := last; ; {
		if req.URL.User != nil {
			return false
		}
		if req.Response == nil {
			return sameHTTPOrigin(original.URL, req.URL)
		}
		previous := req.Response.Request
		if previous == nil ||
			(!sameHTTPOrigin(previous.URL, req.URL) && !isHTTPSUpgrade(previous.URL, req.URL)) {
			return false
		}
		req = previous
	}
}

// canonicalHost returns the lower-cased host of u with the default port for its
// scheme applied when no explicit port is present.
func canonicalHost(u *url.URL) string {
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return strings.ToLower(u.Hostname()) + ":" + port
}

// credential resolves the credential for the given registry.
func (c *Client) credential(ctx context.Context, reg string) (Credential, error) {
	if c.Credential == nil {
		return EmptyCredential, nil
	}
	return c.Credential(ctx, reg)
}

// cache resolves the cache.
// noCache is return if the cache is not configured.
func (c *Client) cache() Cache {
	if c.Cache == nil {
		return noCache{}
	}
	return c.Cache
}

// lookupIPAddr resolves a host name to its IP addresses. It is a variable so
// that tests can inject a fake resolver.
var lookupIPAddr = net.DefaultResolver.LookupIPAddr

var (
	nat64Prefix  = netip.MustParsePrefix("64:ff9b::/96")
	sixTo4Prefix = netip.MustParsePrefix("2002::/16")

	defaultBlockedRealmPrefixes = []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("224.0.0.0/24"),
		netip.MustParsePrefix("ff02::/16"),
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("::/128"),
		netip.MustParsePrefix("100.100.100.200/32"),
		netip.MustParsePrefix("fd00:ec2::254/128"),
		netip.MustParsePrefix("fd00:ec2::23/128"),
		netip.MustParsePrefix("fd20:ce::254/128"),
		netip.MustParsePrefix("168.63.129.16/32"),
	}

	privateRealmPrefixes = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("100.64.0.0/10"),
	}
)

// DefaultBlockedRealmPrefixes returns a fresh copy of the default realm
// address denylist: loopback, link-local (including IMDS), link-local
// multicast, unspecified, and cloud metadata addresses outside link-local.
// RFC 1918, IPv6 unique-local, and carrier-grade NAT are not included.
func DefaultBlockedRealmPrefixes() []netip.Prefix {
	return slices.Clone(defaultBlockedRealmPrefixes)
}

// PrivateRealmPrefixes returns a fresh copy of RFC 1918, IPv6 unique-local
// (fc00::/7), and carrier-grade NAT (100.64.0.0/10) prefixes. Append them to
// DefaultBlockedRealmPrefixes for a strict denylist.
func PrivateRealmPrefixes() []netip.Prefix {
	return slices.Clone(privateRealmPrefixes)
}

// unwrapRealmAddr returns the IPv4 address embedded in an IPv4-mapped,
// NAT64, or 6to4 IPv6 address. Other addresses are returned unmapped.
// The IPv6 zone is stripped so Prefix.Contains can match scoped literals.
func unwrapRealmAddr(addr netip.Addr) netip.Addr {
	addr = addr.Unmap().WithZone("")
	if !addr.Is6() {
		return addr
	}
	b := addr.As16()
	if nat64Prefix.Contains(addr) {
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	if sixTo4Prefix.Contains(addr) {
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]})
	}
	return addr
}

// blockedPrefix reports whether addr, after unwrapping, falls in any prefix.
func blockedPrefix(addr netip.Addr, prefixes []netip.Prefix) (netip.Prefix, bool) {
	check := unwrapRealmAddr(addr)
	for _, prefix := range prefixes {
		if prefix.Contains(check) || prefix.Contains(addr) {
			return prefix, true
		}
	}
	return netip.Prefix{}, false
}

// resolveBlockedPrefixes returns the denylist to apply. nil means defaults;
// a non-nil slice (including empty) is used as given.
func resolveBlockedPrefixes(prefixes []netip.Prefix) []netip.Prefix {
	if prefixes == nil {
		return defaultBlockedRealmPrefixes
	}
	return prefixes
}

const apiPrefix = "/v2/"

var endpointSeparators = []string{
	"/manifests/",
	"/blobs/",
	"/tags/list",
	"/referrers/",
}

// validateRealm rejects bearer token realm URLs that would have the client
// forward credentials to obviously unsafe destinations:
//
//   - schemes other than http or https,
//   - http realms when the registry was contacted over https (TLS downgrade),
//   - hosts that are, or resolve to, an address in prefixes (nil uses
//     DefaultBlockedRealmPrefixes; an empty non-nil slice blocks nothing).
//
// Cross-host realms with a public hostname are permitted, because the
// distribution spec allows a separate token endpoint (e.g. Docker Hub's
// auth.docker.io). When the registry itself is reached at the same hostname
// as the realm, the address check is skipped so loopback and in-cluster
// deployments continue to work.
//
// IPv4-mapped, NAT64, and 6to4 addresses are unwrapped before matching.
// The scheme and downgrade checks always apply.
//
// A realm host that is not an IP literal is resolved with ctx, and the realm
// is rejected if any of its A or AAAA records is in a blocked prefix. If the
// lookup fails, the realm is allowed: behind an HTTP proxy the client may be
// unable to resolve names that the proxy can, and a bogus name fails at dial
// time anyway. The check does not defend against DNS rebinding, where the
// name resolves to a public address here and to a blocked prefix when the
// request is dialed.
//
// validateRealm is also applied to every redirect hop of a token request.
//
// References:
//   - https://github.com/oras-project/oras-go/security/advisories/GHSA-xf85-363p-868w
//   - https://github.com/oras-project/oras-go/security/advisories/GHSA-mm27-wq9c-mxxr
func validateRealm(ctx context.Context, realm string, registryURL *url.URL, prefixes []netip.Prefix) error {
	if realm == "" {
		return nil
	}
	realmURL, err := url.Parse(realm)
	if err != nil {
		return fmt.Errorf("failed to parse bearer realm %q: %w", realm, err)
	}
	switch realmURL.Scheme {
	case "https":
		// always allowed
	case "http":
		if registryURL != nil && registryURL.Scheme == "https" {
			return fmt.Errorf("bearer realm %q uses http but registry was contacted over https", realm)
		}
	default:
		return fmt.Errorf("bearer realm %q uses unsupported scheme %q", realm, realmURL.Scheme)
	}
	host := realmURL.Hostname()
	if registryURL != nil && strings.EqualFold(host, registryURL.Hostname()) {
		return nil
	}
	prefixes = resolveBlockedPrefixes(prefixes)
	if len(prefixes) == 0 {
		return nil
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if prefix, ok := blockedPrefix(addr, prefixes); ok {
			return fmt.Errorf("bearer realm host %q is %s, in blocked prefix %s", host, unwrapRealmAddr(addr), prefix)
		}
		return nil
	}
	addrs, err := lookupIPAddr(ctx, host)
	if err != nil {
		// Do not reject on lookup failure; see the function comment.
		return nil
	}
	for _, ipAddr := range addrs {
		addr, ok := netip.AddrFromSlice(ipAddr.IP)
		if !ok {
			continue
		}
		if prefix, ok := blockedPrefix(addr, prefixes); ok {
			return fmt.Errorf("bearer realm host %q resolves to %s, in blocked prefix %s", host, unwrapRealmAddr(addr), prefix)
		}
	}
	return nil
}

// realmRedirectGuard returns a shallow copy of client whose CheckRedirect
// applies validateRealm to every redirect hop of a token request, measured
// against registryURL, before delegating to the CheckRedirect of client. This
// keeps a validated realm from redirecting the token request into a blocked
// prefix or from https to http. prefixes is the same denylist used for the
// initial realm so redirect hops are evaluated consistently.
// Reference: https://github.com/oras-project/oras-go/security/advisories/GHSA-mm27-wq9c-mxxr
func realmRedirectGuard(client *http.Client, registryURL *url.URL, prefixes []netip.Prefix) *http.Client {
	clientCopy := *client
	checkRedirect := client.CheckRedirect
	clientCopy.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if err := validateRealm(req.Context(), req.URL.String(), registryURL, prefixes); err != nil {
			return fmt.Errorf("redirect of token request rejected: %w", err)
		}
		if checkRedirect != nil {
			return checkRedirect(req, via)
		}
		if len(via) >= defaultMaxRedirects {
			return fmt.Errorf("stopped after %d redirects", defaultMaxRedirects)
		}
		return nil
	}
	return &clientCopy
}

// sendTokenRequest sends a request to a token endpoint like send, but
// re-validates every redirect hop with validateRealm against registryURL, and
// refuses to follow a redirect that would resend the request body to another
// origin. On a 307 or 308 redirect net/http replays the body, which for an
// OAuth2 token request holds the password or refresh token.
// References:
//   - https://github.com/oras-project/oras-go/security/advisories/GHSA-mm27-wq9c-mxxr
//   - https://github.com/oras-project/oras-go/security/advisories/GHSA-xc97-9f2f-9hrx
func (c *Client) sendTokenRequest(req *http.Request, registryURL *url.URL) (*http.Response, error) {
	tokenClient := *c
	tokenClient.Client = realmRedirectGuard(c.client(), registryURL, c.BlockedRealmPrefixes)
	return tokenClient.sendRedirectSafe(req, true)
}

// SetUserAgent sets the user agent for all out-going requests.
func (c *Client) SetUserAgent(userAgent string) {
	if c.Header == nil {
		c.Header = http.Header{}
	}
	c.Header.Set("User-Agent", userAgent)
}

// Do sends the request to the remote server, attempting to resolve
// authentication if 'Authorization' header is not set.
//
// On authentication failure due to bad credential,
//   - Do returns error if it fails to fetch token for bearer auth.
//   - Do returns the registry response without error for basic auth.
func (c *Client) Do(originalReq *http.Request) (*http.Response, error) {
	if auth := originalReq.Header.Get("Authorization"); auth != "" {
		return c.send(originalReq)
	}

	ctx := originalReq.Context()
	req := originalReq.Clone(ctx)

	// attempt cached auth token
	var attemptedKey string
	cache := c.cache()
	host := originalReq.Host
	if host == "" {
		host = originalReq.URL.Host
	}
	scheme, err := cache.GetScheme(ctx, host)
	if err == nil {
		switch scheme {
		case SchemeBasic:
			token, err := cache.GetToken(ctx, host, SchemeBasic, "")
			if err == nil {
				req.Header.Set("Authorization", "Basic "+token)
			}
		case SchemeBearer:
			scopes := GetAllScopesForHost(ctx, host)
			attemptedKey = strings.Join(scopes, " ")
			token, err := cache.GetToken(ctx, host, SchemeBearer, attemptedKey)
			if err == nil {
				req.Header.Set("Authorization", "Bearer "+token)
			}
		}
	}

	resp, err := c.send(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}
	// Resolve credentials only for the original origin and repository, or a
	// same-host HTTPS upgrade.
	authReq := originalReq
	if resp.Request != nil {
		responseURL := resp.Request.URL
		if !sameHTTPOrigin(originalReq.URL, responseURL) {
			if !safeHTTPSUpgrade(originalReq, resp.Request) {
				return resp, nil
			}
			authReq = resp.Request.Clone(ctx)
			authReq.Header = originalReq.Header.Clone()
			if authReq.Method == originalReq.Method {
				authReq.GetBody = originalReq.GetBody
			}
			// Cache keys don't distinguish HTTP from HTTPS.
			cache = noCache{}
		}
	}

	// attempt again with credentials for recognized schemes
	challenge := resp.Header.Get("Www-Authenticate")
	scheme, params := parseChallenge(challenge)
	switch scheme {
	case SchemeBasic:
		resp.Body.Close()

		token, err := cache.Set(ctx, host, SchemeBasic, "", func(ctx context.Context) (string, error) {
			return c.fetchBasicAuth(ctx, host)
		})
		if err != nil {
			return nil, fmt.Errorf("%s %q: %w", resp.Request.Method, resp.Request.URL, err)
		}

		req = authReq.Clone(ctx)
		req.Header.Set("Authorization", "Basic "+token)
	case SchemeBearer:
		resp.Body.Close()

		scopes := GetAllScopesForHost(ctx, host)
		if paramScope := params["scope"]; paramScope != "" {
			// merge hinted scopes with challenged scopes
			scopes = append(scopes, strings.Split(paramScope, " ")...)
			scopes = CleanScopes(scopes)
		}
		key := strings.Join(scopes, " ")

		// attempt the cache again if there is a scope change
		if key != attemptedKey {
			if token, err := cache.GetToken(ctx, host, SchemeBearer, key); err == nil {
				req = authReq.Clone(ctx)
				req.Header.Set("Authorization", "Bearer "+token)
				if err := rewindRequestBody(req); err != nil {
					return nil, err
				}

				resp, err := c.send(req)
				if err != nil {
					return nil, err
				}
				if resp.StatusCode != http.StatusUnauthorized {
					return resp, nil
				}
				resp.Body.Close()
			}
		}

		// attempt with credentials
		realm := params["realm"]
		if err := validateRealm(ctx, realm, authReq.URL, c.BlockedRealmPrefixes); err != nil {
			return nil, fmt.Errorf("%s %q: %w", resp.Request.Method, resp.Request.URL, err)
		}
		service := params["service"]
		token, err := cache.Set(ctx, host, SchemeBearer, key, func(ctx context.Context) (string, error) {
			return c.fetchBearerToken(ctx, authReq.URL, host, realm, service, scopes)
		})
		if err != nil {
			return nil, fmt.Errorf("%s %q: %w", resp.Request.Method, resp.Request.URL, err)
		}

		req = authReq.Clone(ctx)
		req.Header.Set("Authorization", "Bearer "+token)
	default:
		return resp, nil
	}
	if err := rewindRequestBody(req); err != nil {
		return nil, err
	}

	return c.send(req)
}

// fetchBasicAuth fetches a basic auth token for the basic challenge.
func (c *Client) fetchBasicAuth(ctx context.Context, registry string) (string, error) {
	cred, err := c.credential(ctx, registry)
	if err != nil {
		return "", fmt.Errorf("failed to resolve credential: %w", err)
	}
	if cred == EmptyCredential {
		return "", ErrBasicCredentialNotFound
	}
	if cred.Username == "" || cred.Password == "" {
		return "", errors.New("missing username or password for basic auth")
	}
	auth := cred.Username + ":" + cred.Password
	return base64.StdEncoding.EncodeToString([]byte(auth)), nil
}

// fetchBearerToken fetches an access token for the bearer challenge.
//
// registryURL is the URL the registry was contacted at. Every redirect hop of
// the token request is validated against it.
func (c *Client) fetchBearerToken(ctx context.Context, registryURL *url.URL, registry, realm, service string, scopes []string) (string, error) {
	cred, err := c.credential(ctx, registry)
	if err != nil {
		return "", err
	}
	if cred.AccessToken != "" {
		return cred.AccessToken, nil
	}
	if cred == EmptyCredential || (cred.RefreshToken == "" && !c.ForceAttemptOAuth2) {
		return c.fetchDistributionToken(ctx, registryURL, realm, service, scopes, cred.Username, cred.Password)
	}
	return c.fetchOAuth2Token(ctx, registryURL, realm, service, scopes, cred)
}

// fetchDistributionToken fetches an access token as defined by the distribution
// specification.
// It fetches anonymous tokens if no credential is provided.
// References:
// - https://distribution.github.io/distribution/spec/auth/jwt/
// - https://distribution.github.io/distribution/spec/auth/token/
func (c *Client) fetchDistributionToken(ctx context.Context, registryURL *url.URL, realm, service string, scopes []string, username, password string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm, nil)
	if err != nil {
		return "", err
	}
	if username != "" || password != "" {
		req.SetBasicAuth(username, password)
	}
	q := req.URL.Query()
	if service != "" {
		q.Set("service", service)
	}
	for _, scope := range scopes {
		q.Add("scope", scope)
	}
	req.URL.RawQuery = q.Encode()

	resp, err := c.sendTokenRequest(req, registryURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errutil.ParseErrorResponse(resp)
	}

	// As specified in https://distribution.github.io/distribution/spec/auth/token/ section
	// "Token Response Fields", the token is either in `token` or
	// `access_token`. If both present, they are identical.
	var result struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	lr := io.LimitReader(resp.Body, maxResponseBytes)
	if err := json.NewDecoder(lr).Decode(&result); err != nil {
		return "", fmt.Errorf("%s %q: failed to decode response: %w", resp.Request.Method, resp.Request.URL, err)
	}
	if result.AccessToken != "" {
		return result.AccessToken, nil
	}
	if result.Token != "" {
		return result.Token, nil
	}
	return "", fmt.Errorf("%s %q: empty token returned", resp.Request.Method, resp.Request.URL)
}

// fetchOAuth2Token fetches an OAuth2 access token.
// Reference: https://distribution.github.io/distribution/spec/auth/oauth/
func (c *Client) fetchOAuth2Token(ctx context.Context, registryURL *url.URL, realm, service string, scopes []string, cred Credential) (string, error) {
	form := url.Values{}
	if cred.RefreshToken != "" {
		form.Set("grant_type", "refresh_token")
		form.Set("refresh_token", cred.RefreshToken)
	} else if cred.Username != "" && cred.Password != "" {
		form.Set("grant_type", "password")
		form.Set("username", cred.Username)
		form.Set("password", cred.Password)
	} else {
		return "", errors.New("missing username or password for bearer auth")
	}
	form.Set("service", service)
	clientID := c.ClientID
	if clientID == "" {
		clientID = defaultClientID
	}
	form.Set("client_id", clientID)
	if len(scopes) != 0 {
		form.Set("scope", strings.Join(scopes, " "))
	}
	body := strings.NewReader(form.Encode())

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, realm, body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.sendTokenRequest(req, registryURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errutil.ParseErrorResponse(resp)
	}

	var result struct {
		AccessToken string `json:"access_token"`
	}
	lr := io.LimitReader(resp.Body, maxResponseBytes)
	if err := json.NewDecoder(lr).Decode(&result); err != nil {
		return "", fmt.Errorf("%s %q: failed to decode response: %w", resp.Request.Method, resp.Request.URL, err)
	}
	if result.AccessToken != "" {
		return result.AccessToken, nil
	}
	return "", fmt.Errorf("%s %q: empty token returned", resp.Request.Method, resp.Request.URL)
}

// rewindRequestBody tries to rewind the request body if exists.
func rewindRequestBody(req *http.Request) error {
	if req.Body == nil || req.Body == http.NoBody {
		return nil
	}
	if req.GetBody == nil {
		return fmt.Errorf("%s %q: request body is not rewindable", req.Method, req.URL)
	}
	body, err := req.GetBody()
	if err != nil {
		return fmt.Errorf("%s %q: failed to get request body: %w", req.Method, req.URL, err)
	}
	req.Body = body
	return nil
}
