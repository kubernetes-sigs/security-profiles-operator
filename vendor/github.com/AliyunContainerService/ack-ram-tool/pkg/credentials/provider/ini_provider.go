package provider

import (
	"context"
	"fmt"
	"os"
	"path"
)

const (
	defaultINIConfigDir         = "~/.alibabacloud"
	iniConfigFileName           = "credentials"
	defaultINIConfigSectionName = "default"
)

type INIConfigProvider struct {
	cp *CLIConfigProvider
}

type INIConfigProviderOptions struct {
	ConfigPath  string
	SectionName string
	STSEndpoint string
	Logger      Logger
}

func NewIniConfigProvider(opts INIConfigProviderOptions) (*INIConfigProvider, error) {
	opts.applyDefaults()

	data, err := os.ReadFile(opts.ConfigPath)
	if err != nil {
		return nil, NewNotEnableError(err)
	}
	cf, err := parseIniConfig(data).toConfiguration(opts.SectionName)
	if err != nil {
		return nil, NewNotEnableError(
			fmt.Errorf("parse config from %s: %w", opts.ConfigPath, err))
	}

	cp, err := NewCLIConfigProvider(CLIConfigProviderOptions{
		ConfigPath:  "",
		ProfileName: opts.SectionName,
		STSEndpoint: opts.STSEndpoint,
		Logger:      opts.Logger,
		conf:        cf,
	})
	if err != nil {
		return nil, NewNotEnableError(err)
	}

	return &INIConfigProvider{cp: cp}, nil
}

func (i *INIConfigProvider) Credentials(ctx context.Context) (*Credentials, error) {
	return i.cp.Credentials(ctx)
}

func getDefaultINIConfigPath() string {
	dir, err := expandPath(defaultINIConfigDir)
	if err != nil {
		dir = defaultINIConfigDir
	}
	return path.Join(dir, iniConfigFileName)
}

func (o *INIConfigProviderOptions) applyDefaults() {
	if o.ConfigPath == "" {
		o.ConfigPath = getDefaultINIConfigPath()
	}
	if o.SectionName == "" {
		if v := os.Getenv(envProfileName); v != "" {
			o.SectionName = v
		} else {
			o.SectionName = defaultINIConfigSectionName
		}
	}
	if o.Logger == nil {
		o.Logger = DefaultLogger
	}
}
