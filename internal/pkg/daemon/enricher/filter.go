/*
Copyright 2025 The Kubernetes Authors.

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
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/go-logr/logr"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
)

func GetEnricherFilters(enricherFiltersJsonStr string, logger logr.Logger) ([]types.EnricherFilterOptions, error) {
	var enricherFilters []types.EnricherFilterOptions
	if err := json.Unmarshal([]byte(enricherFiltersJsonStr), &enricherFilters); err != nil {
		logger.Error(err, "failed to unmarshal enricher filters",
			"enricherFiltersJsonStr", enricherFiltersJsonStr)

		return nil, err
	}

	// Lower the priority value, higher the precedence
	sort.Slice(enricherFilters, func(i, j int) bool {
		return enricherFilters[i].Priority < enricherFilters[j].Priority
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

func matchPathFilterLabel(label string, filter types.EnricherFilterOptions, logMap map[string]any) bool {
	subLabels := strings.SplitN(label, "/", 2)

	if len(subLabels) == 2 {
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

	for _, value := range *filter.MatchValues {
		if reflect.DeepEqual(value, logValue) {
			return true
		}

		// Support int values for syscallids.
		// `any` can't be used due to json restrictions.
		valueInt, errValue := strconv.Atoi(value)
		if errValue == nil {
			if retrievedInt, ok := convertToInt(logValue); ok {
				return valueInt == retrievedInt
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
		if v < int64(int(v)) || v > int64(int(v)) {
			// Outside int32 range
			return 0, false
		}

		return int(v), true
	default:
		return 0, false
	}
}
