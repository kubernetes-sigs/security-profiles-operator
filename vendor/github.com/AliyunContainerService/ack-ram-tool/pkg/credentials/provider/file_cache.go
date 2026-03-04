package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"time"
)

type FileCacheProvider struct {
	cacheDir string
	cp       CredentialsProvider

	expiryWindow time.Duration
	logger       Logger
	logPrefix    string

	nowFunc func() time.Time
}

type FileCacheProviderOptions struct {
	ExpiryWindow time.Duration
	Logger       Logger
	LogPrefix    string
}

func NewFileCacheProvider(cacheDir string, cp CredentialsProvider, opts FileCacheProviderOptions) *FileCacheProvider {
	opts.applyDefaults()

	p := &FileCacheProvider{
		cp:           cp,
		cacheDir:     cacheDir,
		expiryWindow: opts.ExpiryWindow,
		logger:       opts.Logger,
		logPrefix:    opts.LogPrefix,
	}
	return p
}

func (f *FileCacheProvider) Credentials(ctx context.Context) (*Credentials, error) {
	cred, err := f.getFromCache()

	if err != nil || cred == nil || cred.expired(f.now(), f.expiryWindow) {
		f.logger.Debug(fmt.Sprintf("%s cache file not exist or expired", f.logPrefix))
		cred, err := f.getCredentials(ctx)
		if err != nil {
			return nil, err
		}

		_ = f.saveCredentials(cred)
		return cred, err
	}

	f.logger.Debug(fmt.Sprintf("%s use data from cache", f.logPrefix))
	return cred, nil
}

func (f *FileCacheProvider) saveCredentials(cred *Credentials) error {
	if err := f.ensureCacheDir(); err != nil {
		f.logger.Error(err, fmt.Sprintf("%s ensure cache dir %s failed: %s", f.logPrefix, f.cacheDir, err))
		return nil
	}

	p := f.cacheFilePath()
	data, err := json.Marshal(cred)
	if err != nil {
		f.logger.Error(err, fmt.Sprintf("%s marshal credentials failed: %s", f.logPrefix, err))
		return err
	}

	encoded := base64.StdEncoding.EncodeToString(data)
	if err := os.WriteFile(p, []byte(encoded), 0600); err != nil {
		f.logger.Error(err, fmt.Sprintf("%s write cache file %s failed: %s", f.logPrefix, p, err))
		return err
	}

	return nil
}

func (f *FileCacheProvider) getCredentials(ctx context.Context) (*Credentials, error) {
	cred, err := f.cp.Credentials(ctx)
	if err != nil {
		f.logger.Error(err, fmt.Sprintf("%s get credentials faild: %s", f.logPrefix, err))
		return nil, err
	}
	return cred, err
}

func (f *FileCacheProvider) getFromCache() (*Credentials, error) {
	p := f.cacheFilePath()
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, err
		}
		f.logger.Error(err, fmt.Sprintf("%s read cache file %s failed: %s", f.logPrefix, p, err))
		return nil, err
	}

	rawJson, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		f.logger.Error(err, fmt.Sprintf("%s decode cache file %s failed: %s", f.logPrefix, p, err))
		return nil, err
	}

	var cred Credentials
	if err := json.Unmarshal(rawJson, &cred); err != nil {
		f.logger.Error(err, fmt.Sprintf("%s unmarshal cache file %s failed: %s", f.logPrefix, p, err))
		return nil, err
	}
	return &cred, err
}

func (f *FileCacheProvider) ensureCacheDir() error {
	return os.MkdirAll(f.cacheDir, 0750)
}

func (f *FileCacheProvider) cacheFilePath() string {
	return path.Join(f.cacheDir, "cred")
}

func (f *FileCacheProvider) now() time.Time {
	if f.nowFunc == nil {
		return time.Now()
	}
	return f.nowFunc()
}

func (f *FileCacheProviderOptions) applyDefaults() {
	if f.ExpiryWindow == 0 {
		f.ExpiryWindow = defaultExpiryWindowForAssumeRole
	}
	if f.Logger == nil {
		f.Logger = defaultLog
	}
	if f.LogPrefix == "" {
		f.LogPrefix = "[FileCacheProvider]"
	}
}
