package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/AliyunContainerService/ack-ram-tool/pkg/ecsmetadata"
)

const (
	defaultExpiryWindow               = time.Minute * 30
	defaultECSMetadataServerEndpoint  = "http://100.100.100.200"
	envECSMetadataServerEndpoint      = "ALIBABA_CLOUD_IMDS_ENDPOINT"
	envIMDSV2Disabled                 = "ALIBABA_CLOUD_IMDSV2_DISABLED"
	envIMDSRoleName                   = "ALIBABA_CLOUD_ECS_METADATA"
	defaultECSMetadataTokenTTLSeconds = 3600
	defaultClientTimeout              = time.Second * 30
)

type ECSMetadataProvider struct {
	u *Updater

	endpoint                string
	roleName                string
	disableToken            bool
	metadataToken           string
	metadataTokenTTLSeconds int
	metadataTokenExp        time.Time

	client *ecsmetadata.Client
	Logger Logger
}

type ECSMetadataProviderOptions struct {
	Endpoint  string
	Timeout   time.Duration
	Transport http.RoundTripper

	RoleName                string
	MetadataTokenTTLSeconds int
	DisableToken            bool

	ExpiryWindow  time.Duration
	RefreshPeriod time.Duration
	Logger        Logger
}

func NewECSMetadataProvider(opts ECSMetadataProviderOptions) *ECSMetadataProvider {
	opts.applyDefaults()
	cops := opts.toClientOptions()
	wrapper := func(rt http.RoundTripper) http.RoundTripper {
		w := &commonHttpClient{
			delegatedRoundTripper: rt,
			logger:                opts.Logger,
		}
		return w
	}
	cops.TransportWrappers = append(cops.TransportWrappers, wrapper)
	client, err := ecsmetadata.NewClient(cops)
	if err != nil {
		client, _ = ecsmetadata.NewClient(ecsmetadata.ClientOptions{
			TransportWrappers: []ecsmetadata.TransportWrapper{wrapper},
		})
	}

	e := &ECSMetadataProvider{
		roleName: opts.RoleName,
		client:   client,
		Logger:   opts.Logger,
	}
	e.u = NewUpdater(e.getCredentials, UpdaterOptions{
		ExpiryWindow:  opts.ExpiryWindow,
		RefreshPeriod: opts.RefreshPeriod,
		Logger:        opts.Logger,
		LogPrefix:     "[ECSMetadataProvider]",
	})
	e.u.Start(context.TODO())

	return e
}

func (e *ECSMetadataProvider) Credentials(ctx context.Context) (*Credentials, error) {
	return e.u.Credentials(ctx)
}

func (e *ECSMetadataProvider) Stop(ctx context.Context) {
	e.u.Stop(ctx)
}

type ecsMetadataStsResponse struct {
	AccessKeyId     string `json:"AccessKeyId"`
	AccessKeySecret string `json:"AccessKeySecret"`
	SecurityToken   string `json:"SecurityToken"`
	Expiration      string `json:"Expiration"`
	LastUpdated     string `json:"LastUpdated"`
	Code            string `json:"Code"`
}

func (e *ECSMetadataProvider) getCredentials(ctx context.Context) (*Credentials, error) {
	roleName, err := e.GetRoleName(ctx)
	if err != nil {
		if e, ok := err.(*httpError); ok && e.code == 404 {
			return nil, NewNotEnableError(fmt.Errorf("get role name from ecs metadata failed: %w", err))
		}
		var httperr *ecsmetadata.HTTPError
		if errors.As(err, &httperr) && httperr.StatusCode == 404 {
			return nil, NewNotEnableError(fmt.Errorf("get role name from ecs metadata failed: %w", err))
		}
		return nil, err
	}
	obj, err := e.client.GetRoleCredentials(ctx, roleName)
	if err != nil {
		return nil, err
	}
	if obj.AccessKeyId == "" || obj.AccessKeySecret == "" {
		return nil, fmt.Errorf("parse credentials got unexpected data: %+v", *obj)
	}

	return &Credentials{
		AccessKeyId:     obj.AccessKeyId,
		AccessKeySecret: obj.AccessKeySecret,
		SecurityToken:   obj.SecurityToken,
		Expiration:      obj.Expiration,
	}, nil
}

func (e *ECSMetadataProvider) GetRoleName(ctx context.Context) (string, error) {
	if e.roleName != "" {
		return e.roleName, nil
	}
	return e.client.GetRoleName(ctx)
}

func (e *ECSMetadataProvider) GetMedataDataWithToken(ctx context.Context, method, path string) (string, error) {
	data, err := e.client.GetMetaData(ctx, method, path)
	return string(data), err
}

func (e *ECSMetadataProvider) logger() Logger {
	if e.Logger != nil {
		return e.Logger
	}
	return defaultLog
}

func (o *ECSMetadataProviderOptions) applyDefaults() {
	if o.Timeout <= 0 {
		o.Timeout = defaultClientTimeout
	}
	if o.Transport == nil {
		ts := http.DefaultTransport.(*http.Transport).Clone()
		o.Transport = ts
	}
	if o.Endpoint == "" {
		if v := os.Getenv(envECSMetadataServerEndpoint); v != "" {
			o.Endpoint = v
		} else {
			o.Endpoint = defaultECSMetadataServerEndpoint
		}
	} else {
		o.Endpoint = strings.TrimRight(o.Endpoint, "/")
	}
	if !o.DisableToken {
		if v := os.Getenv(envIMDSV2Disabled); v != "" {
			if b, err := strconv.ParseBool(v); err == nil && b {
				o.DisableToken = true
			}
		}
	}
	if o.MetadataTokenTTLSeconds == 0 {
		o.MetadataTokenTTLSeconds = defaultECSMetadataTokenTTLSeconds
	}
	if o.RoleName == "" {
		if v := os.Getenv(envIMDSRoleName); v != "" {
			o.RoleName = v
		}
	}
	if o.ExpiryWindow == 0 {
		o.ExpiryWindow = defaultExpiryWindow
	}
	if o.Logger == nil {
		o.Logger = defaultLog
	}
}

func (o *ECSMetadataProviderOptions) toClientOptions() ecsmetadata.ClientOptions {
	return ecsmetadata.ClientOptions{
		Endpoint:          o.Endpoint,
		RoleName:          o.RoleName,
		DisableIMDSV2:     o.DisableToken,
		TokenTTLSeconds:   o.MetadataTokenTTLSeconds,
		TransportWrappers: nil,
		Timeout:           o.Timeout,
		NowFunc:           nil,
		DisableRetry:      false,
		RetryOptions:      nil,
	}
}
