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
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"text/tabwriter"

	"github.com/pkg/errors"
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

func Get() *Info {
	info, _ := debug.ReadBuildInfo()

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
	}
}

// String returns the string representation of the version info.
func (i *Info) String() string {
	b := strings.Builder{}
	const padding = 2
	w := tabwriter.NewWriter(&b, 0, 0, padding, ' ', 0)

	fmt.Fprintf(w, "Version:\t%s\n", i.Version)
	fmt.Fprintf(w, "GitCommit:\t%s\n", i.GitCommit)
	fmt.Fprintf(w, "GitCommitDate:\t%s\n", i.GitCommitDate)
	fmt.Fprintf(w, "GitTreeState:\t%s\n", i.GitTreeState)
	fmt.Fprintf(w, "BuildDate:\t%s\n", i.BuildDate)
	fmt.Fprintf(w, "GoVersion:\t%s\n", i.GoVersion)
	fmt.Fprintf(w, "Compiler:\t%s\n", i.Compiler)
	fmt.Fprintf(w, "Platform:\t%s\n", i.Platform)
	fmt.Fprintf(w, "Libseccomp:\t%s\n", i.Libseccomp)
	fmt.Fprintf(w, "Libbpf:\t%s\n", i.Libbpf)
	fmt.Fprintf(w, "BuildTags:\t%s\n", i.BuildTags)
	fmt.Fprintf(w, "LDFlags:\t%s\n", i.LDFlags)
	fmt.Fprintf(w, "CGOLDFlags:\t%s\n", i.CGOLDFlags)
	fmt.Fprintf(w, "Dependencies:\n  %s\n", strings.Join(i.Dependencies, "\n  "))

	w.Flush()
	return b.String()
}

// JSONString returns the JSON representation of the version info.
func (i *Info) JSONString() (string, error) {
	b, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		return "", errors.Wrap(err, "marshal info as JSON")
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
