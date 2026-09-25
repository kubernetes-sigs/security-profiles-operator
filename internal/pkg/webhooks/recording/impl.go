/*
Copyright The Kubernetes Authors.

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

package recording

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
)

type defaultImpl struct {
	client client.Client
}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate -header ../../../../hack/boilerplate/boilerplate.generatego.txt
//counterfeiter:generate . impl
type impl interface {
	ListProfileRecordings(
		context.Context,
		...client.ListOption,
	) (*profilerecordingapi.ProfileRecordingList, error)
}

func (d *defaultImpl) ListProfileRecordings(
	ctx context.Context, opts ...client.ListOption,
) (*profilerecordingapi.ProfileRecordingList, error) {
	profileRecordings := &profilerecordingapi.ProfileRecordingList{}
	if err := d.client.List(ctx, profileRecordings, opts...); err != nil {
		return nil, fmt.Errorf("list profile recordings: %w", err)
	}

	return profileRecordings, nil
}
