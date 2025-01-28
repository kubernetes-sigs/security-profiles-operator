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

package version

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"text/tabwriter"
)

var (
	buildDate string // build date in ISO8601 format, output of $(date -u +'%Y-%m-%dT%H:%M:%SZ')
	version   string // the current version of the operator
)

type Info struct {
	Version       string   `json:"version,omitempty"`
	GitCommit     string   `json:"gitCommit,omitempty"`
	GitCommitDate string   `json:"gitCommitDate,omitempty"`
	GitTreeState  string   `json:"gitTreeState,omitempty"`
	BuildDate     string   `json:"buildDate,omitempty"`
	GoVersion     string   `json:"goVersion,omitempty"`
	Compiler      string   `json:"compiler,omitempty"`
	Platform      string   `json:"platform,omitempty"`
	Libseccomp    string   `json:"libseccomp,omitempty"`
	Libbpf        string   `json:"libbpf,omitempty"`
	BuildTags     string   `json:"buildTags,omitempty"`
	LDFlags       string   `json:"ldFlags,omitempty"`
	CGOLDFlags    string   `json:"cgoLdflags,omitempty"`
	Dependencies  []string `json:"dependencies,omitempty"`
}

func Get() (*Info, error) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return nil, errors.New("unable to retrieve build info")
	}

	const unknown = "unknown"
	gitCommit := unknown
	gitTreeState := "clean"
	gitCommitDate := unknown
	buildTags := unknown
	ldFlags := unknown
	cgoLdflags := unknown

	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			gitCommit = s.Value

		case "vcs.modified":
			if s.Value == "true" {
				gitTreeState = "dirty"
			}

		case "vcs.time":
			gitCommitDate = s.Value

		case "-tags":
			buildTags = s.Value

		case "-ldflags":
			ldFlags = s.Value

		case "CGO_LDFLAGS":
			cgoLdflags = s.Value
		}
	}

	dependencies := []string{}
	for _, d := range info.Deps {
		dependencies = append(
			dependencies,
			fmt.Sprintf("%s %s %s", d.Path, d.Version, d.Sum),
		)
	}

	return &Info{
		Version:       version,
		GitCommit:     gitCommit,
		GitCommitDate: gitCommitDate,
		GitTreeState:  gitTreeState,
		BuildDate:     buildDate,
		GoVersion:     info.GoVersion,
		Compiler:      runtime.Compiler,
		Platform:      fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		Libseccomp:    libseccompVersion(),
		Libbpf:        libbpfVersion(),
		BuildTags:     buildTags,
		LDFlags:       ldFlags,
		CGOLDFlags:    cgoLdflags,
		Dependencies:  dependencies,
	}, nil
}

// String returns the string representation of the version info.
func (i *Info) String() string {
	b := strings.Builder{}

	const padding = 2
	w := tabwriter.NewWriter(&b, 0, 0, padding, ' ', 0)

	v := reflect.ValueOf(*i)

	t := v.Type()
	for i := range t.NumField() {
		field := t.Field(i)
		value := v.FieldByName(field.Name)

		valueString := ""
		//nolint:exhaustive,nolintlint // we ignore missing switch cases on purpose
		switch field.Type.Kind() {
		case reflect.Bool:
			valueString = strconv.FormatBool(value.Bool())

		case reflect.Slice:
			// Only expecting []string here; ignore other slices.
			if s, ok := value.Interface().([]string); ok {
				const sep = "\n  "
				valueString = sep + strings.Join(s, sep)
			}

		case reflect.String:
			valueString = value.String()
		}

		if valueString != "" {
			fmt.Fprintf(w, "%s:\t%s", field.Name, valueString)

			if i+1 < t.NumField() {
				fmt.Fprintf(w, "\n")
			}
		}
	}

	w.Flush()

	return b.String()
}

// JSONString returns the JSON representation of the version info.
func (i *Info) JSONString() (string, error) {
	b, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal info as JSON: %w", err)
	}

	return string(b), nil
}

// AsKeyValues returns a key value slice of the info.
func (i *Info) AsKeyValues() []interface{} {
	return []interface{}{
		"version", i.Version,
		"gitCommit", i.GitCommit,
		"gitCommitDate", i.GitCommitDate,
		"gitTreeState", i.GitTreeState,
		"buildDate", i.BuildDate,
		"goVersion", i.GoVersion,
		"compiler", i.Compiler,
		"platform", i.Platform,
		"libseccomp", i.Libseccomp,
		"libbpf", i.Libbpf,
		"buildTags", i.BuildTags,
		"ldFlags", i.LDFlags,
		"cgoldFlags", i.CGOLDFlags,
		"dependencies", strings.Join(i.Dependencies, ","),
	}
}
