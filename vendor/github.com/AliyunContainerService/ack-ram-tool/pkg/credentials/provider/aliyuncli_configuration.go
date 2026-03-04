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
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
)

const (
	defaultCLIConfigDir         = "~/.aliyun"
	cliConfigFileName           = "config.json"
	defaultCLIConfigProfileName = "default"
)

type Configuration struct {
	CurrentProfile string    `json:"current"`
	Profiles       []Profile `json:"profiles"`
	MetaPath       string    `json:"meta_path"`
	//Plugins 		[]Plugin `json:"plugin"`
}

func newConfiguration() *Configuration {
	return &Configuration{
		CurrentProfile: defaultCLIConfigProfileName,
		Profiles: []Profile{
			newProfile(defaultCLIConfigProfileName),
		},
	}
}

func (c *Configuration) getProfile(pn string) (Profile, bool) {
	for _, p := range c.Profiles {
		if p.Name == pn {
			return p, true
		}
	}
	return Profile{Name: pn}, false
}

func getDefaultConfigPath() string {
	dir, err := expandPath(defaultCLIConfigDir)
	if err != nil {
		dir = defaultCLIConfigDir
	}
	return path.Join(dir, cliConfigFileName)
}

func loadConfiguration(inputPath string) (conf *Configuration, err error) {
	_, statErr := os.Stat(inputPath)
	if os.IsNotExist(statErr) {
		conf = newConfiguration()
		return
	}

	bytes, err := os.ReadFile(path.Clean(inputPath))
	if err != nil {
		err = fmt.Errorf("reading config from '%s' failed %v", inputPath, err)
		return
	}

	conf, err = newConfigFromBytes(bytes)
	return
}

func newConfigFromBytes(bytes []byte) (conf *Configuration, err error) {
	conf = newConfiguration()
	err = json.Unmarshal(bytes, conf)
	return
}

func expandPath(path string) (string, error) {
	if len(path) > 0 && path[0] == '~' {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		path = filepath.Join(home, path[1:])
	}
	return path, nil
}
