package provider

import (
	"context"
	"errors"
	"time"
)

type FunctionProvider struct {
	getCredentials func(ctx context.Context) (*Credentials, error)

	u *Updater
}

type FunctionProviderOptions struct {
	RefreshPeriod time.Duration
	ExpiryWindow  time.Duration
	Logger        Logger
	LogPrefix     string
}

func NewFunctionProvider(getCredentials func(ctx context.Context) (*Credentials, error)) *FunctionProvider {
	return NewFunctionProviderWithOptions(getCredentials, FunctionProviderOptions{})
}

func NewFunctionProviderWithOptions(getCredentials func(ctx context.Context) (*Credentials, error),
	opts FunctionProviderOptions) *FunctionProvider {
	opts.applyDefaults()

	f := &FunctionProvider{
		getCredentials: getCredentials,
	}

	f.u = NewUpdater(f.getCredentials, UpdaterOptions{
		ExpiryWindow:  opts.ExpiryWindow,
		RefreshPeriod: opts.RefreshPeriod,
		Logger:        opts.Logger,
		LogPrefix:     opts.LogPrefix,
	})
	f.u.Start(context.TODO())

	return f
}

func (f *FunctionProvider) Credentials(ctx context.Context) (*Credentials, error) {
	if f.getCredentials == nil {
		return nil, NewNotEnableError(errors.New("getCredentials function is nil"))
	}

	return f.u.Credentials(ctx)
}

func (f *FunctionProvider) Stop(ctx context.Context) {
	f.u.Stop(ctx)
}

func (f *FunctionProvider) setNowFunc(t func() time.Time) {
	f.u.nowFunc = t
}

func (f *FunctionProviderOptions) applyDefaults() {
	if f.ExpiryWindow == 0 {
		f.ExpiryWindow = time.Minute * 1
	}
	if f.Logger == nil {
		f.Logger = defaultLog
	}
	if f.LogPrefix == "" {
		f.LogPrefix = "[FunctionProvider]"
	}
}
