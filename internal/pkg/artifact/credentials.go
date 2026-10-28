/*
Copyright The Kubernetes Authors.

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

package artifact

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/google/go-containerregistry/pkg/authn"
	ggcrname "github.com/google/go-containerregistry/pkg/name"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"
)

// setRepoCredentials configures the registry authentication of the
// repository: the username and password if given, otherwise the docker config
// credentials. The signatures are read and written through the same
// repository.
func (a *Artifact) setRepoCredentials(repo *remote.Repository, username, password string) {
	var warnOnce sync.Once

	// A broken docker config, like a credential helper missing from the
	// PATH, must not break registries which work anonymously.
	credential := func(ctx context.Context, hostport string) (auth.Credential, error) {
		cred, err := keychainCredential(ctx, hostport)
		if err != nil {
			warnOnce.Do(func() {
				a.logger.Info(
					"Unable to use the docker config credentials, accessing the registry anonymously",
					"registry",
					hostport,
					"error",
					err.Error(),
				)
			})

			return auth.EmptyCredential, nil //nolint:nilerr // anonymous access is the fallback
		}

		return cred, nil
	}

	if username != "" || password != "" {
		a.logger.Info("Using username and password")

		credential = auth.StaticCredential(
			repo.Reference.Registry,
			auth.Credential{Username: username, Password: password},
		)
	}

	if repo.PlainHTTP && !loopbackRegistry(repo.Reference.Registry) {
		credential = a.warnPlainHTTP(credential)
	}

	repo.Client = &auth.Client{
		Client:     retry.DefaultClient,
		Cache:      auth.DefaultCache,
		Credential: credential,
	}
}

// warnPlainHTTP warns once that the credentials go over plain HTTP, where
// anybody on the way can read them.
func (a *Artifact) warnPlainHTTP(credential auth.CredentialFunc) auth.CredentialFunc {
	var warnOnce sync.Once

	return func(ctx context.Context, hostport string) (auth.Credential, error) {
		cred, err := credential(ctx, hostport)
		if err == nil && cred != auth.EmptyCredential {
			warnOnce.Do(func() {
				a.logger.Info("WARNING: Sending the registry credentials over plain HTTP",
					"registry", hostport)
			})
		}

		return cred, err
	}
}

// loopbackRegistry reports whether the registry runs on this host, where
// plain HTTP does not leave it.
func loopbackRegistry(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}

	if host == "localhost" {
		return true
	}

	ip := net.ParseIP(host)

	return ip != nil && ip.IsLoopback()
}

// keychainCredential resolves the registry credentials from the docker config
// and its credential helpers, the default keychain of cosign and most other
// registry clients. Registries without an entry are accessed anonymously.
// Docker Hub is reached through index.docker.io, the name of the docker
// config, because the repositories are named after the parsed references.
func keychainCredential(_ context.Context, hostport string) (auth.Credential, error) {
	registry, err := ggcrname.NewRegistry(hostport)
	if err != nil {
		return auth.EmptyCredential, fmt.Errorf("parse registry %s: %w", hostport, err)
	}

	authenticator, err := authn.DefaultKeychain.Resolve(registry)
	if err != nil {
		return auth.EmptyCredential, fmt.Errorf("resolve credentials for %s: %w", hostport, err)
	}

	config, err := authenticator.Authorization()
	if err != nil {
		return auth.EmptyCredential, fmt.Errorf("get credentials for %s: %w", hostport, err)
	}

	return auth.Credential{
		Username:     config.Username,
		Password:     config.Password,
		RefreshToken: config.IdentityToken,
		AccessToken:  config.RegistryToken,
	}, nil
}
