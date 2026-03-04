package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	envProfileName = "ALIBABA_CLOUD_PROFILE"
)

type profileWrapper struct {
	cp   Profile
	conf *Configuration

	stsEndpoint string
	client      *http.Client
	logger      Logger

	getProviderForUnknownMode func(p Profile) (CredentialsProvider, error)
}

type CLIConfigProvider struct {
	profile *profileWrapper
	logger  Logger

	pr   CredentialsProvider
	lock sync.Mutex
}

type CLIConfigProviderOptions struct {
	ConfigPath  string
	ProfileName string
	STSEndpoint string
	Logger      Logger

	GetProviderForUnknownMode func(p Profile) (CredentialsProvider, error)

	conf *Configuration
}

func NewCLIConfigProvider(opts CLIConfigProviderOptions) (*CLIConfigProvider, error) {
	opts.applyDefaults()
	logger := opts.Logger

	conf, profile, err := loadProfile(opts.ConfigPath, opts.ProfileName, opts.conf)
	if err != nil {
		return nil, NewNotEnableError(fmt.Errorf("load profile: %w", err))
	}
	if err := profile.validate(); err != nil {
		return nil, NewNotEnableError(fmt.Errorf("validate profile: %w", err))
	}
	logger.Debug(fmt.Sprintf("use profile name: %s", profile.Name))
	c := &CLIConfigProvider{
		profile: &profileWrapper{
			cp:          profile,
			conf:        conf,
			stsEndpoint: opts.STSEndpoint,
			client: &http.Client{
				Timeout: time.Second * 30,
			},
			logger:                    logger,
			getProviderForUnknownMode: opts.GetProviderForUnknownMode,
		},
		logger: logger,
	}
	return c, nil
}

func loadProfile(path string, name string, conf *Configuration) (*Configuration, Profile, error) {
	var p Profile
	var err error

	if conf == nil {
		conf, err = loadConfiguration(path)
		if err != nil {
			return nil, p, fmt.Errorf("init config: %w", err)
		}
	}
	if name == "" {
		name = conf.CurrentProfile
	}
	p, ok := conf.getProfile(name)
	if !ok {
		return nil, p, fmt.Errorf("unknown profile %s", name)
	}
	return conf, p, nil
}

func (c *CLIConfigProvider) Credentials(ctx context.Context) (*Credentials, error) {
	p, err := c.getAndUpdateProvider()
	if err != nil {
		return nil, err
	}
	return p.Credentials(ctx)
}

func (c *CLIConfigProvider) getAndUpdateProvider() (CredentialsProvider, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.pr != nil {
		return c.pr, nil
	}

	pr, err := c.profile.getProvider()
	if err != nil {
		return nil, err
	}
	c.pr = pr

	return pr, nil
}

func (p *profileWrapper) getProvider() (CredentialsProvider, error) {
	cp := p.cp

	switch cp.Mode {
	case AK:
		p.logger.Debug(fmt.Sprintf("using %s mode", cp.Mode))
		return p.getCredentialsByAK()
	case StsToken:
		p.logger.Debug(fmt.Sprintf("using %s mode", cp.Mode))
		return p.getCredentialsBySts()
	case RamRoleArn:
		p.logger.Debug(fmt.Sprintf("using %s mode", cp.Mode))
		return p.getCredentialsByRoleArn()
	case EcsRamRole:
		p.logger.Debug(fmt.Sprintf("using %s mode", cp.Mode))
		return p.getCredentialsByEcsRamRole()
	case RamRoleArnWithEcs:
		p.logger.Debug(fmt.Sprintf("using %s mode", cp.Mode))
		return p.getCredentialsByRamRoleArnWithEcs()
	case ChainableRamRoleArn:
		p.logger.Debug(fmt.Sprintf("using %s mode", cp.Mode))
		return p.getCredentialsByChainableRamRoleArn()
	case External:
		p.logger.Debug(fmt.Sprintf("using %s mode", cp.Mode))
		return p.getCredentialsByExternal()
	case CredentialsURI:
		p.logger.Debug(fmt.Sprintf("using %s mode", cp.Mode))
		return p.getCredentialsByCredentialsURI()
	default:
		if p.getProviderForUnknownMode != nil {
			return p.getProviderForUnknownMode(cp)
		}
		return nil, fmt.Errorf("unexcepted credentials mode: %s", cp.Mode)
	}
}

func (p *profileWrapper) getCredentialsByAK() (CredentialsProvider, error) {
	cp := p.cp

	return NewAccessKeyProvider(cp.AccessKeyId, cp.AccessKeySecret), nil
}

func (p *profileWrapper) getCredentialsBySts() (CredentialsProvider, error) {
	cp := p.cp

	return NewSTSTokenProvider(cp.AccessKeyId, cp.AccessKeySecret, cp.StsToken), nil
}

func (p *profileWrapper) getCredentialsByRoleArn() (CredentialsProvider, error) {
	cp := p.cp

	preP, _ := p.getCredentialsByAK()
	if cp.StsToken != "" {
		preP, _ = p.getCredentialsBySts()
	}

	return p.getCredentialsByRoleArnWithPro(preP)
}

func (p *profileWrapper) getCredentialsByRoleArnWithPro(preP CredentialsProvider) (CredentialsProvider, error) {
	cp := p.cp

	credP := NewRoleArnProvider(preP, cp.RamRoleArn, RoleArnProviderOptions{
		STSEndpoint: p.stsEndpoint,
		SessionName: cp.RoleSessionName,
		Logger:      p.logger,
		ExternalId:  cp.ExternalId,
	})
	return credP, nil
}

func (p *profileWrapper) getCredentialsByEcsRamRole() (CredentialsProvider, error) {
	cp := p.cp

	credP := NewECSMetadataProvider(ECSMetadataProviderOptions{
		RoleName: cp.RamRoleName,
		Logger:   p.logger,
	})
	return credP, nil
}

//func (p *profileWrapper) getCredentialsByPrivateKey() (credentials.Credential, error) {
//
//}

func (p *profileWrapper) getCredentialsByRamRoleArnWithEcs() (CredentialsProvider, error) {
	preP, err := p.getCredentialsByEcsRamRole()
	if err != nil {
		return nil, err
	}
	return p.getCredentialsByRoleArnWithPro(preP)
}

func (p *profileWrapper) getCredentialsByChainableRamRoleArn() (CredentialsProvider, error) {
	cp := p.cp
	profileName := cp.SourceProfile

	p.logger.Debug(fmt.Sprintf("get credentials from source profile %s", profileName))
	source, loaded := p.conf.getProfile(profileName)
	if !loaded {
		return nil, fmt.Errorf("can not load the source profile: " + profileName)
	}

	newP := p.clone(source)
	preP, err := newP.getProvider()
	if err != nil {
		return nil, err
	}

	p.logger.Debug(fmt.Sprintf("using role arn by current profile %s", cp.Name))
	return p.getCredentialsByRoleArnWithPro(preP)
}

func (p *profileWrapper) getCredentialsByExternal() (CredentialsProvider, error) {
	cp := p.cp
	args := strings.Fields(cp.ProcessCommand)
	cmd := exec.Command(args[0], args[1:]...) // #nosec G204
	p.logger.Debug(fmt.Sprintf("running external program: %s", cp.ProcessCommand))

	genmsg := func(buf []byte, err error) string {
		message := fmt.Sprintf(`run external program to get credentials faild:
  command: %s
  output: %s
  error: %s`,
			cp.ProcessCommand, string(buf), err.Error())
		return message
	}

	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	allOutput := stderr.String() + "\n" + stdout.String()
	if err != nil {
		message := genmsg([]byte(allOutput), err)
		return nil, errors.New(message)
	}

	buf := stdout.Bytes()
	var newCP Profile
	err = json.Unmarshal(buf, &newCP)
	if err != nil {
		if pp := tryToParseProfileFromOutput(string(buf)); pp != nil {
			newCP = *pp
		} else {
			message := genmsg([]byte(allOutput), err)
			return nil, errors.New(message)
		}
	}

	p.logger.Debug(fmt.Sprintf("using profile from output of external program"))
	newP := p.clone(newCP)
	return newP.getProvider()
}

func (w *profileWrapper) clone(newCP Profile) profileWrapper {
	return profileWrapper{
		client:                    w.client,
		conf:                      w.conf,
		cp:                        newCP,
		getProviderForUnknownMode: w.getProviderForUnknownMode,
		logger:                    w.logger,
		stsEndpoint:               w.stsEndpoint,
	}
}

var regexpCredJSON = regexp.MustCompile(`{[^}]+"mode":[^}]+}`)

func tryToParseProfileFromOutput(output string) *Profile {
	ret := regexpCredJSON.FindAllString(output, 1)
	if len(ret) < 1 {
		return nil
	}
	credJSON := ret[0]
	var p Profile
	if err := json.Unmarshal([]byte(credJSON), &p); err == nil && p.Mode != "" {
		return &p
	}
	return nil
}

func (p *profileWrapper) getCredentialsByCredentialsURI() (CredentialsProvider, error) {
	cp := p.cp
	uri := cp.CredentialsURI
	if uri == "" {
		uri = os.Getenv(envCredentialsURI)
	}
	if uri == "" {
		return nil, fmt.Errorf("invalid credentials uri")
	}
	p.logger.Debug(fmt.Sprintf("get credentials from uri %s", uri))

	newPr := NewURIProvider(uri, URIProviderOptions{})
	return newPr, nil
}

func (c *CLIConfigProvider) ProfileName() string {
	return c.profile.cp.Name
}

func (o *CLIConfigProviderOptions) applyDefaults() {
	if o.ConfigPath == "" {
		o.ConfigPath = getDefaultConfigPath()
	}
	if o.ProfileName == "" {
		if v := os.Getenv(envProfileName); v != "" {
			o.ProfileName = v
		}
	}
	if o.Logger == nil {
		o.Logger = DefaultLogger
	}
}
