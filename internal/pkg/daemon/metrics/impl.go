/*
Copyright 2021 The Kubernetes Authors.

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

package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

type defaultImpl struct{}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate -header ../../../../hack/boilerplate/boilerplate.generatego.txt
//counterfeiter:generate . impl
type impl interface {
	Register(c prometheus.Collector) error
	ListenAndServe(addr string, handler http.Handler) error
}

func (d *defaultImpl) Register(c prometheus.Collector) error {
	return prometheus.Register(c)
}

func (d *defaultImpl) ListenAndServe(addr string, handler http.Handler) error {
	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: util.DefaultReadHeaderTimeout,
	}
	return server.ListenAndServe()
}
