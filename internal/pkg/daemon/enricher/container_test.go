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

package enricher

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractContainerID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		cgroupLine string
		want       string
	}{
		{
			"Should extract crio ID",
			//nolint:lll
			`4:net_cls,net_prio:/kubepods/besteffort/pod26ba375c-2266-4ecc-bf2d-b626db8762af/crio-af208fd68bf39a07a439ed0c9b6609b9ae63ecd8a5f1a2af3e0db48b945b320a`,
			"af208fd68bf39a07a439ed0c9b6609b9ae63ecd8a5f1a2af3e0db48b945b320a",
		},
		{
			"Should return empty when not found",
			`0::/system.slice/crio.service`,
			"",
		},
		{
			"Should extract crio ID ending with .scope",
			`0::/system.slice/crio-conmon-5819a498721cf8bb7e334809c9e48aa310bfc98801eb8017034ad17fb0749920.scope`,
			"5819a498721cf8bb7e334809c9e48aa310bfc98801eb8017034ad17fb0749920",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := extractID(tt.cgroupLine)
			require.Equal(t, tt.want, got)
		})
	}
}
