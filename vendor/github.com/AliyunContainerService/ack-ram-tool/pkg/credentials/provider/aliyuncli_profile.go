// Copyright (c) 2009-present, Alibaba Cloud All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package provider

import (
	"fmt"
)

type AuthenticateMode string

const (
	AK                  = AuthenticateMode("AK")
	StsToken            = AuthenticateMode("StsToken")
	RamRoleArn          = AuthenticateMode("RamRoleArn")
	EcsRamRole          = AuthenticateMode("EcsRamRole")
	RsaKeyPair          = AuthenticateMode("RsaKeyPair")
	RamRoleArnWithEcs   = AuthenticateMode("RamRoleArnWithRoleName")
	ChainableRamRoleArn = AuthenticateMode("ChainableRamRoleArn")
	External            = AuthenticateMode("External")
	CredentialsURI      = AuthenticateMode("CredentialsURI")
)

type Profile struct {
	Name                      string           `json:"name"`
	Mode                      AuthenticateMode `json:"mode"`
	AccessKeyId               string           `json:"access_key_id,omitempty"`
	AccessKeySecret           string           `json:"access_key_secret,omitempty"`
	StsToken                  string           `json:"sts_token,omitempty"`
	StsRegion                 string           `json:"sts_region,omitempty"`
	RamRoleName               string           `json:"ram_role_name,omitempty"`
	RamRoleArn                string           `json:"ram_role_arn,omitempty"`
	RoleSessionName           string           `json:"ram_session_name,omitempty"`
	ExternalId                string           `json:"external_id,omitempty"`
	SourceProfile             string           `json:"source_profile,omitempty"`
	PrivateKey                string           `json:"private_key,omitempty"`
	KeyPairName               string           `json:"key_pair_name,omitempty"`
	ExpiredSeconds            int              `json:"expired_seconds,omitempty"`
	Verified                  string           `json:"verified,omitempty"`
	RegionId                  string           `json:"region_id,omitempty"`
	OutputFormat              string           `json:"output_format,omitempty"`
	Language                  string           `json:"language,omitempty"`
	Site                      string           `json:"site,omitempty"`
	ReadTimeout               int              `json:"retry_timeout,omitempty"`
	ConnectTimeout            int              `json:"connect_timeout,omitempty"`
	RetryCount                int              `json:"retry_count,omitempty"`
	ProcessCommand            string           `json:"process_command,omitempty"`
	CredentialsURI            string           `json:"credentials_uri,omitempty"`
	OIDCProviderARN           string           `json:"oidc_provider_arn,omitempty"`
	OIDCTokenFile             string           `json:"oidc_token_file,omitempty"`
	CloudSSOSignInUrl         string           `json:"cloud_sso_sign_in_url,omitempty"`
	AccessToken               string           `json:"access_token,omitempty"`                  // for CloudSSO, read only
	CloudSSOAccessTokenExpire int64            `json:"cloud_sso_access_token_expire,omitempty"` // for CloudSSO, read only
	StsExpiration             int64            `json:"sts_expiration,omitempty"`                // for CloudSSO, read only
	CloudSSOAccessConfig      string           `json:"cloud_sso_access_config,omitempty"`       // for CloudSSO
	CloudSSOAccountId         string           `json:"cloud_sso_account_id,omitempty"`          // for CloudSSO, read only
	parent                    *Configuration   //`json:"-"`
}

func newProfile(name string) Profile {
	return Profile{
		Name:         name,
		Mode:         "",
		OutputFormat: "json",
		Language:     "en",
	}
}

func (cp *Profile) validate() error {
	if cp.Mode == "" {
		return fmt.Errorf("profile %s is not configure yet, run `aliyun configure --profile %s` first", cp.Name, cp.Name)
	}

	switch cp.Mode {
	case AK:
		return cp.validateAK()
	case StsToken:
		err := cp.validateAK()
		if err != nil {
			return err
		}
		if cp.StsToken == "" {
			return fmt.Errorf("invalid sts_token")
		}
	case RamRoleArn:
		err := cp.validateAK()
		if err != nil {
			return err
		}
		if cp.RamRoleArn == "" {
			return fmt.Errorf("invalid ram_role_arn")
		}
		if cp.RoleSessionName == "" {
			return fmt.Errorf("invalid role_session_name")
		}
	case EcsRamRole, RamRoleArnWithEcs:
	case RsaKeyPair:
		if cp.PrivateKey == "" {
			return fmt.Errorf("invalid private_key")
		}
		if cp.KeyPairName == "" {
			return fmt.Errorf("invalid key_pair_name")
		}
	case External:
		if cp.ProcessCommand == "" {
			return fmt.Errorf("invalid process_command")
		}
	case CredentialsURI:
		if cp.CredentialsURI == "" {
			return fmt.Errorf("invalid credentials_uri")
		}
	case ChainableRamRoleArn:
		if cp.SourceProfile == "" {
			return fmt.Errorf("invalid source_profile")
		}
		if cp.RamRoleArn == "" {
			return fmt.Errorf("invalid ram_role_arn")
		}
		if cp.RoleSessionName == "" {
			return fmt.Errorf("invalid role_session_name")
		}
	}
	return nil
}

func (cp *Profile) getParent() *Configuration {
	return cp.parent
}

func (cp *Profile) validateAK() error {
	if len(cp.AccessKeyId) == 0 {
		return fmt.Errorf("invalid access_key_id: %s", cp.AccessKeyId)
	}
	if len(cp.AccessKeySecret) == 0 {
		return fmt.Errorf("invaild access_key_secret: %s", cp.AccessKeySecret)
	}
	return nil
}
