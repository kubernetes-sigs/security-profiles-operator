/*
Copyright 2023 The Kubernetes Authors.

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

package puller

import (
	"context"
	"os"

	"github.com/go-logr/logr"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli"
)

type defaultImpl struct{}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate -header ../../../../hack/boilerplate/boilerplate.generatego.txt
//counterfeiter:generate . impl
type impl interface {
	Pull(string, string, string, *v1.Platform, bool) (*artifact.PullResult, error)
	WriteFile(string, []byte, os.FileMode) error
}

func (*defaultImpl) Pull(
	from, username, password string, platform *v1.Platform, disableSignatureVerification bool,
) (*artifact.PullResult, error) {
	return artifact.New(logr.New(&cli.LogSink{})).Pull(
		context.Background(), from, username, password, platform, disableSignatureVerification,
	)
}

func (*defaultImpl) WriteFile(name string, data []byte, perm os.FileMode) error {
	return os.WriteFile(name, data, perm)
}
