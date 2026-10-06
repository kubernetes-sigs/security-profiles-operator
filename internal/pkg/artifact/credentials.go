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

	repo.Client = &auth.Client{
		Client:     retry.DefaultClient,
		Cache:      auth.DefaultCache,
		Credential: credential,
	}
}

// keychainCredential resolves the registry credentials from the docker config
// and its credential helpers, the default keychain of cosign and most other
// registry clients. Registries without an entry are accessed anonymously.
func keychainCredential(_ context.Context, hostport string) (auth.Credential, error) {
	// ORAS talks to Docker Hub through its registry host, which the docker
	// config knows by the name of the index.
	if hostport == dockerHubRegistryHost {
		hostport = ggcrname.DefaultRegistry
	}

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
