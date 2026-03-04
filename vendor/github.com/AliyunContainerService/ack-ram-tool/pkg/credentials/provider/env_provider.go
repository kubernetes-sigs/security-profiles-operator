package provider

import (
	"context"
	"errors"
	"fmt"
	"os"
)

const (
	envAccessKeyId     = "ALIBABA_CLOUD_ACCESS_KEY_ID"
	envAccessKeySecret = "ALIBABA_CLOUD_ACCESS_KEY_SECRET"
	envSecurityToken   = "ALIBABA_CLOUD_SECURITY_TOKEN"
)

type EnvProvider struct {
	cp CredentialsProvider
}

type EnvProviderOptions struct {
	EnvAccessKeyId     string
	EnvAccessKeySecret string
	EnvSecurityToken   string

	EnvRoleArn         string
	EnvOIDCProviderArn string
	EnvOIDCTokenFile   string

	EnvCredentialsURI    string
	EnvConfigFile        string
	EnvConfigSectionName string

	EnvIMDSRoleName string

	STSEndpoint string
	Logger      Logger
}

func NewEnvProvider(opts EnvProviderOptions) *EnvProvider {
	opts.applyDefaults()

	e := &EnvProvider{}
	e.cp = e.getProvider(opts)

	return e
}

func (e *EnvProvider) Credentials(ctx context.Context) (*Credentials, error) {
	cred, err := e.cp.Credentials(ctx)

	if err != nil {
		if IsNoAvailableProviderError(err) {
			return nil, NewNotEnableError(fmt.Errorf("not found credentials from env: %w", err))
		}
		return nil, err
	}

	return cred.DeepCopy(), nil
}

func (e *EnvProvider) Stop(ctx context.Context) {
	if s, ok := e.cp.(Stopper); ok {
		s.Stop(ctx)
	}
}

func (e *EnvProvider) getProvider(opts EnvProviderOptions) CredentialsProvider {
	accessKeyId := os.Getenv(opts.EnvAccessKeyId)
	accessKeySecret := os.Getenv(opts.EnvAccessKeySecret)
	securityToken := os.Getenv(opts.EnvSecurityToken)
	roleArn := os.Getenv(opts.EnvRoleArn)
	oidcProviderArn := os.Getenv(opts.EnvOIDCProviderArn)
	oidcTokenFile := os.Getenv(opts.EnvOIDCTokenFile)
	credentialsURI := os.Getenv(opts.EnvCredentialsURI)
	iniConfigPath := os.Getenv(opts.EnvConfigFile)
	iniConfigSectionName := os.Getenv(opts.EnvConfigSectionName)
	imdsRoleName := os.Getenv(opts.EnvIMDSRoleName)

	switch {
	case accessKeyId != "" && accessKeySecret != "" && securityToken != "":
		cp := NewSTSTokenProvider(
			os.Getenv(opts.EnvAccessKeyId),
			os.Getenv(opts.EnvAccessKeySecret),
			os.Getenv(opts.EnvSecurityToken),
		)
		if roleArn == "" {
			return cp
		}
		return NewRoleArnProvider(cp, roleArn, RoleArnProviderOptions{
			STSEndpoint: opts.STSEndpoint,
			Logger:      opts.Logger,
		})

	case accessKeyId != "" && accessKeySecret != "":
		cp := NewAccessKeyProvider(
			os.Getenv(opts.EnvAccessKeyId),
			os.Getenv(opts.EnvAccessKeySecret),
		)
		if roleArn == "" {
			return cp
		}
		return NewRoleArnProvider(cp, roleArn, RoleArnProviderOptions{
			STSEndpoint: opts.STSEndpoint,
			Logger:      opts.Logger,
		})

	case roleArn != "" && oidcProviderArn != "" && oidcTokenFile != "":
		return NewOIDCProvider(OIDCProviderOptions{
			RoleArn:         roleArn,
			OIDCProviderArn: oidcProviderArn,
			OIDCTokenFile:   oidcTokenFile,
			STSEndpoint:     opts.STSEndpoint,
			Logger:          opts.Logger,
		})

	case credentialsURI != "":
		return NewURIProvider(credentialsURI, URIProviderOptions{
			Logger: opts.Logger,
		})

	case imdsRoleName != "":
		return NewECSMetadataProvider(ECSMetadataProviderOptions{
			RoleName: imdsRoleName,
			Logger:   opts.Logger,
		})

	case iniConfigPath != "":
		cp, err := NewIniConfigProvider(INIConfigProviderOptions{
			ConfigPath:  iniConfigPath,
			SectionName: iniConfigSectionName,
			STSEndpoint: opts.STSEndpoint,
			Logger:      opts.Logger,
		})
		if err != nil {
			opts.Logger.Debug(err.Error())
		} else {
			return cp
		}
	}

	return &errorProvider{
		err: NewNoAvailableProviderError(
			errors.New("no validated credentials were found in environment variables")),
	}
}

func (o *EnvProviderOptions) applyDefaults() {
	if o.EnvAccessKeyId == "" {
		o.EnvAccessKeyId = envAccessKeyId
	}
	if o.EnvAccessKeySecret == "" {
		o.EnvAccessKeySecret = envAccessKeySecret
	}
	if o.EnvSecurityToken == "" {
		o.EnvSecurityToken = envSecurityToken
	}

	if o.EnvRoleArn == "" {
		o.EnvRoleArn = defaultEnvRoleArn
	}
	if o.EnvOIDCProviderArn == "" {
		o.EnvOIDCProviderArn = defaultEnvOIDCProviderArn
	}
	if o.EnvOIDCTokenFile == "" {
		o.EnvOIDCTokenFile = defaultEnvOIDCTokenFile
	}

	if o.EnvCredentialsURI == "" {
		o.EnvCredentialsURI = envCredentialsURI
	}
	if o.EnvConfigFile == "" {
		o.EnvConfigFile = envINIConfigFile
	}
	if o.EnvConfigSectionName == "" {
		o.EnvConfigSectionName = envProfileName
	}

	if o.EnvIMDSRoleName == "" {
		o.EnvIMDSRoleName = envIMDSRoleName
	}

	if o.Logger == nil {
		o.Logger = DefaultLogger
	}
}
