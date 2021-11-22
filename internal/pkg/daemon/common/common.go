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

package common

import (
	"context"
	"os"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	spodv1alpha1 "sigs.k8s.io/security-profiles-operator/api/spod/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

// GetSPODName returns the name of the SPOD instance we're currently running
// on.
func GetSPODName() string {
	name := os.Getenv(config.SPOdNameEnvKey)
	if name == "" {
		// Return the default spod name
		return config.SPOdName
	}
	return name
}

// GetSPOD returns the SPOD instance we're currently running on.
func GetSPOD(ctx context.Context, cli client.Client) (*spodv1alpha1.SecurityProfilesOperatorDaemon, error) {
	spod := &spodv1alpha1.SecurityProfilesOperatorDaemon{}
	if err := cli.Get(ctx, types.NamespacedName{
		Name:      GetSPODName(),
		Namespace: config.GetOperatorNamespace(),
	}, spod); err != nil {
		return nil, err
	}

	return spod, nil
}
