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

package enricher

import (
	"encoding/json"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
)

// FuzzEnricherFilters feeds arbitrary filter configurations and log lines into
// the enricher filtering. Parsed filters are ordered by priority, and applying
// them results either in the default level or in the level of one filter.
func FuzzEnricherFilters(f *testing.F) {
	for _, seed := range []struct{ filters, log string }{
		{`[]`, `{}`},
		{`[`, `{}`},
		{`null`, `null`},
		{
			`[{"priority":101,"level":"Metadata","matchKeys":["namespace"],"matchValues":["default"]}]`,
			`{"namespace":"default"}`,
		},
		{
			`[{"priority":2,"level":"None","matchKeys":["syscallID"],"matchValues":["23"]},` +
				`{"priority":1,"level":"Metadata","matchKeys":["resource/pod"]}]`,
			`{"syscallID":23,"resource":{"pod":"nginx"}}`,
		},
		{
			`[{"priority":-1,"level":"None","matchKeys":["a/b/c"],"matchValues":[]}]`,
			`{"a":{"b":{"c":[1,2]}}}`,
		},
		{`[{"priority":1,"level":"None","matchKeys":["/"]}]`, `{"":{"":true}}`},
		{`[{"priority":"x"}]`, `{"a":1}`},
	} {
		f.Add(seed.filters, seed.log)
	}

	f.Fuzz(func(t *testing.T, filtersJSON, logJSON string) {
		filters, err := GetEnricherFilters(filtersJSON, logr.Discard())
		if err != nil {
			require.Nil(t, filters)

			return
		}

		for i := 1; i < len(filters); i++ {
			require.LessOrEqual(t, filters[i-1].Priority, filters[i].Priority)
		}

		var logMap map[string]any
		if err := json.Unmarshal([]byte(logJSON), &logMap); err != nil {
			logMap = map[string]any{"log": logJSON}
		}

		level := ApplyEnricherFilters(logMap, filters)
		if level == types.EnricherLogLevelMetadata {
			return
		}

		found := false

		for _, filter := range filters {
			if filter.Level == level {
				found = true

				break
			}
		}

		require.True(t, found, "level %q is not set by any filter", level)
	})
}
