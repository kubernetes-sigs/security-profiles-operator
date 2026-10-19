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
	"cmp"
	"encoding/json"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/go-logr/logr"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
)

// GetEnricherFilters parses the filters of the enricher from their JSON
// encoding and sorts them by priority. A filter with an unknown level counts
// as Metadata, like in the released versions, and gets a warning: a typo like
// "none" logs the lines the filter is meant to drop. A filter without
// matchKeys gets a warning too, as it never matches.
func GetEnricherFilters(
	enricherFiltersJsonStr string,
	logger logr.Logger,
) ([]types.EnricherFilterOptions, error) {
	var enricherFilters []types.EnricherFilterOptions
	if err := json.Unmarshal([]byte(enricherFiltersJsonStr), &enricherFilters); err != nil {
		logger.Error(err, "failed to unmarshal enricher filters",
			"enricherFiltersJsonStr", enricherFiltersJsonStr)

		return nil, err
	}

	for _, filter := range enricherFilters {
		if filter.Level != types.EnricherLogLevelMetadata &&
			filter.Level != types.EnricherLogLevelNone {
			logger.Info(
				"WARNING: unknown enricher filter level, using Metadata, "+
					"valid levels are Metadata and None",
				"level", filter.Level, "priority", filter.Priority,
			)
		}

		if len(filter.MatchKeys) == 0 {
			logger.Info(
				"WARNING: enricher filter without matchKeys never matches",
				"level", filter.Level, "priority", filter.Priority,
			)
		}
	}

	// Lower the priority value, higher the precedence
	slices.SortStableFunc(enricherFilters, func(a, b types.EnricherFilterOptions) int {
		return cmp.Compare(a.Priority, b.Priority)
	})

	return enricherFilters, nil
}

func ApplyEnricherFilters(logMap map[string]any,
	enricherFilters []types.EnricherFilterOptions,
) types.EnricherLogLevel {
	for _, filter := range enricherFilters {
		if matchAnyFilterLabel(filter, logMap) {
			return filter.Level
		}
	}

	return types.EnricherLogLevelMetadata
}

func matchAnyFilterLabel(filter types.EnricherFilterOptions, logMap map[string]any) bool {
	for _, label := range filter.MatchKeys {
		if matchPathFilterLabel(label, filter, logMap) {
			return true
		}
	}

	return false
}

func matchPathFilterLabel(
	label string,
	filter types.EnricherFilterOptions,
	logMap map[string]any,
) bool {
	subLabels := strings.SplitN(label, "/", 2)

	if len(subLabels) == 2 {
		// The JSON enricher emits the nested values as map[string]any.
		if subMap, ok := logMap[subLabels[0]].(map[string]any); ok {
			// Recursive search for the filter label with path.
			// For example resource/pod.
			return matchPathFilterLabel(subLabels[1], filter, subMap)
		}

		return false
	}

	if logValue, exists := logMap[label]; exists {
		return matchAnyFilterValue(logValue, filter)
	}

	return false
}

func matchAnyFilterValue(logValue any, filter types.EnricherFilterOptions) bool {
	if filter.MatchValues == nil || len(*filter.MatchValues) == 0 {
		return true
	}

	// A list, like the syscalls of the JSON enricher, matches if any of its
	// elements does.
	if values, ok := logValue.([]string); ok {
		return slices.ContainsFunc(values, func(value string) bool {
			return matchAnyFilterValue(value, filter)
		})
	}

	for _, value := range *filter.MatchValues {
		if reflect.DeepEqual(value, logValue) {
			return true
		}

		// Support int values for syscallids.
		// `any` can't be used due to json restrictions.
		valueInt, errValue := strconv.Atoi(value)
		if errValue == nil {
			if retrievedInt, ok := convertToInt(logValue); ok && valueInt == retrievedInt {
				return true
			}
		}
	}

	return false
}

func convertToInt(val any) (int, bool) {
	switch v := val.(type) {
	case int:
		return v, true
	case int8:
		return int(v), true
	case int16:
		return int(v), true
	case int32:
		return int(v), true
	case int64:
		// Only an int narrower than 64 bits cannot hold every value.
		if int64(int(v)) != v {
			return 0, false
		}

		return int(v), true
	case uint32:
		return int(v), true
	case *uint32:
		// Uid and Gid are optional, so the record carries a pointer. Without
		// these two cases a filter on uid/gid with a numeric matchValue never
		// matches anything.
		if v == nil {
			return 0, false
		}

		return int(*v), true
	default:
		return 0, false
	}
}
