/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
)

const (
	deploymentYAML = "deploy/operator.yaml"
	configMapName  = "default-profiles"
	profilesDir    = "profiles"
)

type matcher struct {
	foundConfigMapType bool
	foundConfigMapName bool
	foundData          bool
	replace            bool
}

func main() {
	file, err := os.Open(deploymentYAML)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	match := &matcher{}
	res := ""
	for scanner.Scan() {
		line := scanner.Text()

		// Add the profiles to the found target YAML
		if match.replace {
			if err := addJSONProfiles(&res); err != nil {
				log.Print(err)
			}
			break
		}

		// look for config map types
		if line == "kind: ConfigMap" {
			match.foundConfigMapType = true
		}

		// look for the right config map
		if match.foundConfigMapType && line == "  name: "+configMapName {
			match.foundConfigMapName = true
		}

		// look for the data section
		if match.foundConfigMapType && match.foundConfigMapName && line == "data:" {
			match.foundData = true
		}

		// start replacing
		if match.foundConfigMapType && match.foundConfigMapName && match.foundData {
			match.replace = true
		}

		res += line + "\n"
	}

	if err := ioutil.WriteFile(deploymentYAML, []byte(res), 0o600); err != nil {
		log.Print(err)
	}
}

func addJSONProfiles(res *string) error {
	files, err := ioutil.ReadDir(profilesDir)
	if err != nil {
		return errors.Wrapf(err, "reading %s", profilesDir)
	}

	for _, file := range files {
		fileName := file.Name()
		if !strings.HasSuffix(fileName, ".json") {
			continue
		}

		targetFile := filepath.Join(profilesDir, fileName)
		fileData, err := ioutil.ReadFile(targetFile)
		if err != nil {
			return errors.Wrapf(err, "reading file %s", targetFile)
		}

		parsedJSON := &bytes.Buffer{}
		if err := json.Compact(parsedJSON, fileData); err != nil {
			return errors.Wrapf(err, "parsing JSON of file %s", targetFile)
		}

		*res += fmt.Sprintf("  %s: |-\n", fileName)
		*res += fmt.Sprintf("    %s\n", parsedJSON.String())
	}

	return nil
}
