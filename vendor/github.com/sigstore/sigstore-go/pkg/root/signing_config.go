// Copyright 2024 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package root

import (
	"fmt"
	"os"

	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"google.golang.org/protobuf/encoding/protojson"
)

const SigningConfigMediaType01 = "application/vnd.dev.sigstore.signingconfig.v0.1+json"

type SigningConfig struct {
	signingConfig *prototrustroot.SigningConfig
}

func (sc *SigningConfig) FulcioCertificateAuthorityURL() string {
	return sc.signingConfig.GetCaUrl()
}

func (sc *SigningConfig) OIDCProviderURL() string {
	return sc.signingConfig.GetOidcUrl()
}

func (sc *SigningConfig) RekorLogURLs() []string {
	return sc.signingConfig.GetTlogUrls()
}

func (sc *SigningConfig) TimestampAuthorityURLs() []string {
	return sc.signingConfig.GetTsaUrls()
}

func (sc *SigningConfig) WithFulcioCertificateAuthorityURL(fulcioURL string) *SigningConfig {
	sc.signingConfig.CaUrl = fulcioURL
	return sc
}

func (sc *SigningConfig) WithOIDCProviderURL(oidcURL string) *SigningConfig {
	sc.signingConfig.OidcUrl = oidcURL
	return sc
}

func (sc *SigningConfig) WithRekorLogURLs(logURLs []string) *SigningConfig {
	sc.signingConfig.TlogUrls = logURLs
	return sc
}

func (sc *SigningConfig) AddRekorLogURLs(logURLs ...string) *SigningConfig {
	sc.signingConfig.TlogUrls = append(sc.signingConfig.TlogUrls, logURLs...)
	return sc
}

func (sc *SigningConfig) WithTimestampAuthorityURLs(tsaURLs []string) *SigningConfig {
	sc.signingConfig.TsaUrls = tsaURLs
	return sc
}

func (sc *SigningConfig) AddTimestampAuthorityURLs(tsaURLs ...string) *SigningConfig {
	sc.signingConfig.TsaUrls = append(sc.signingConfig.TsaUrls, tsaURLs...)
	return sc
}

func (sc SigningConfig) String() string {
	return fmt.Sprintf("{CA: %v, OIDC: %v, RekorLogs: %v, TSAs: %v, MediaType: %s}",
		sc.FulcioCertificateAuthorityURL(), sc.OIDCProviderURL(), sc.RekorLogURLs(), sc.TimestampAuthorityURLs(), SigningConfigMediaType01)
}

// NewSigningConfig initializes a SigningConfig object from a mediaType string, Fulcio certificate
// authority URL, OIDC provider URL, list of Rekor transpraency log URLs, and a list of
// timestamp authorities.
func NewSigningConfig(mediaType string,
	fulcioCertificateAuthority string,
	oidcProvider string,
	rekorLogs []string,
	timestampAuthorities []string) (*SigningConfig, error) {
	if mediaType != SigningConfigMediaType01 {
		return nil, fmt.Errorf("unsupported SigningConfig media type, must be: %s", SigningConfigMediaType01)
	}
	sc := &SigningConfig{
		signingConfig: &prototrustroot.SigningConfig{
			MediaType: mediaType,
			CaUrl:     fulcioCertificateAuthority,
			OidcUrl:   oidcProvider,
			TlogUrls:  rekorLogs,
			TsaUrls:   timestampAuthorities,
		},
	}
	return sc, nil
}

// NewSigningConfigFromProtobuf returns a Sigstore signing configuration.
func NewSigningConfigFromProtobuf(sc *prototrustroot.SigningConfig) (*SigningConfig, error) {
	if sc.GetMediaType() != SigningConfigMediaType01 {
		return nil, fmt.Errorf("unsupported SigningConfig media type: %s", sc.GetMediaType())
	}
	return &SigningConfig{signingConfig: sc}, nil
}

// NewSigningConfigFromPath returns a Sigstore signing configuration from a file.
func NewSigningConfigFromPath(path string) (*SigningConfig, error) {
	scJSON, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return NewSigningConfigFromJSON(scJSON)
}

// NewSigningConfigFromJSON returns a Sigstore signing configuration from JSON.
func NewSigningConfigFromJSON(rootJSON []byte) (*SigningConfig, error) {
	pbSC, err := NewSigningConfigProtobuf(rootJSON)
	if err != nil {
		return nil, err
	}

	return NewSigningConfigFromProtobuf(pbSC)
}

// NewSigningConfigProtobuf returns a Sigstore signing configuration as a protobuf.
func NewSigningConfigProtobuf(scJSON []byte) (*prototrustroot.SigningConfig, error) {
	pbSC := &prototrustroot.SigningConfig{}
	err := protojson.Unmarshal(scJSON, pbSC)
	if err != nil {
		return nil, err
	}
	return pbSC, nil
}

// FetchSigningConfig fetches the public-good Sigstore signing configuration from TUF.
func FetchSigningConfig() (*SigningConfig, error) {
	return FetchSigningConfigWithOptions(tuf.DefaultOptions())
}

// FetchSigningConfig fetches the public-good Sigstore signing configuration with the given options from TUF.
func FetchSigningConfigWithOptions(opts *tuf.Options) (*SigningConfig, error) {
	client, err := tuf.New(opts)
	if err != nil {
		return nil, err
	}
	return GetSigningConfig(client)
}

// FetchSigningConfig fetches the public-good Sigstore signing configuration target from TUF.
func GetSigningConfig(c *tuf.Client) (*SigningConfig, error) {
	jsonBytes, err := c.GetTarget("signing_config.json")
	if err != nil {
		return nil, err
	}
	return NewSigningConfigFromJSON(jsonBytes)
}
