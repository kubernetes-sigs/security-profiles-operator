package provider

import (
	"fmt"
	"regexp"
	"strings"
)

type iniConfig struct {
	items []iniConfigItem
}

type iniConfigItem struct {
	section string
	config  map[string]iniConfigItemValue
}

type iniConfigItemValue string

var (
	reIniConfigItem              = regexp.MustCompile(`(?m)\s*(?:\[([^]]+)\]([^[]+))`)
	reIniConfigLineSuffixComment = regexp.MustCompile(`(?m)[#;]+.+$`)
)

func parseIniConfig(input []byte) iniConfig {
	var config iniConfig
	var tidyInput strings.Builder
	lines := strings.Split(string(input), "\n")
	for _, line := range lines {
		line := strings.TrimSpace(line)
		if line == "" ||
			strings.HasPrefix(line, ";") ||
			strings.HasPrefix(line, "#") {
			continue
		}
		line = reIniConfigLineSuffixComment.ReplaceAllLiteralString(line, "")
		tidyInput.WriteString(line + "\n")
	}
	multipleParts := reIniConfigItem.FindAllStringSubmatch(tidyInput.String(), -1)
	if len(multipleParts) == 0 {
		return config
	}

	for _, parts := range multipleParts {
		name := strings.TrimSpace(parts[1])
		item := iniConfigItem{
			section: name,
			config:  map[string]iniConfigItemValue{},
		}
		for _, line := range strings.Split(parts[2], "\n") {
			line := strings.TrimSpace(line)
			kv := strings.SplitN(line, "=", 2)
			if len(kv) != 2 {
				continue
			}
			k, v := strings.TrimSpace(kv[0]), strings.Trim(strings.TrimSpace(kv[1]), `'"`)
			item.config[k] = iniConfigItemValue(v)
		}
		config.items = append(config.items, item)
	}

	return config
}

func (c iniConfigItem) Type() string {
	if len(c.config) == 0 {
		return ""
	}
	return c.config["type"].String()
}

func (v iniConfigItemValue) String() string {
	return string(v)
}

func (c iniConfig) toConfiguration(sectionName string) (*Configuration, error) {
	inicfg := c.getSection(sectionName)
	if inicfg.section == "" {
		return nil, fmt.Errorf("section %s is not found", sectionName)
	}

	pf := inicfg.toProfile()
	if err := pf.validate(); err != nil {
		return nil, err
	}
	cfg := &Configuration{
		CurrentProfile: sectionName,
		Profiles:       []Profile{pf},
		MetaPath:       "",
	}
	return cfg, nil
}

func (c iniConfig) getSection(name string) iniConfigItem {
	for _, item := range c.items {
		if item.section == name {
			return item
		}
	}
	return iniConfigItem{}
}

func (c iniConfigItem) toProfile() Profile {
	pf := Profile{
		Name:            c.section,
		Mode:            "",
		AccessKeyId:     c.config["access_key_id"].String(),
		AccessKeySecret: c.config["access_key_secret"].String(),
		StsToken:        c.config["sts_token"].String(),
		StsRegion:       c.config["sts_region"].String(),
		RamRoleName:     c.config["role_name"].String(),
		RamRoleArn:      c.config["role_arn"].String(),
		RoleSessionName: c.config["role_session_name"].String(),
		ProcessCommand:  c.config["process_command"].String(),
		CredentialsURI:  c.config["credentials_uri"].String(),
	}

	switch c.Type() {
	case "access_key":
		pf.Mode = AK
	case "sts":
		pf.Mode = StsToken
	case "ram_role_arn":
		pf.Mode = RamRoleArn
	case "credentials_uri":
		pf.Mode = CredentialsURI
	case "ecs_ram_role":
		pf.Mode = EcsRamRole
	case "external":
		pf.Mode = External
	}

	return pf
}
