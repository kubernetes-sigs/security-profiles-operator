package provider

import (
	"context"
	"fmt"
	"time"
)

type RemoteProvider struct {
	u *Updater

	getRawData func(context.Context) ([]byte, error)
	decoder    func(ctx context.Context, data []byte) (*Credentials, error)
}

type RemoteProviderOptions struct {
	RefreshPeriod time.Duration
	ExpiryWindow  time.Duration
	Logger        Logger
	LogPrefix     string
}

func NewRemoteProvider(getRawData func(ctx context.Context) ([]byte, error),
	decoder func(ctx context.Context, data []byte) (*Credentials, error),
	opts RemoteProviderOptions) *RemoteProvider {
	opts.applyDefaults()

	e := &RemoteProvider{
		getRawData: getRawData,
		decoder:    decoder,
	}
	e.u = NewUpdater(e.getCredentials, UpdaterOptions{
		ExpiryWindow:  opts.ExpiryWindow,
		RefreshPeriod: opts.RefreshPeriod,
		Logger:        opts.Logger,
		LogPrefix:     opts.LogPrefix,
	})
	e.u.Start(context.TODO())

	return e
}

func (f *RemoteProvider) Credentials(ctx context.Context) (*Credentials, error) {
	return f.u.Credentials(ctx)
}

func (f *RemoteProvider) Stop(ctx context.Context) {
	f.u.Stop(ctx)
}

func (f *RemoteProvider) getCredentials(ctx context.Context) (*Credentials, error) {
	if f.getRawData == nil {
		return nil, NewNotEnableError(fmt.Errorf("getRawData function is nil"))
	}
	data, err := f.getRawData(ctx)
	if err != nil {
		return nil, fmt.Errorf("get raw data from remote failed: %w", err)
	}

	cred, err := f.decoder(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("decode data from remote failed: %w", err)
	}
	return cred, nil
}

func (f *RemoteProviderOptions) applyDefaults() {
	if f.ExpiryWindow == 0 {
		f.ExpiryWindow = defaultExpiryWindow
	}
	if f.Logger == nil {
		f.Logger = defaultLog
	}
	if f.LogPrefix == "" {
		f.LogPrefix = "[RemoteProvider]"
	}
}
