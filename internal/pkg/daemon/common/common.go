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
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/release-utils/helpers"

	spodv1alpha1 "sigs.k8s.io/security-profiles-operator/api/spod/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

// GetSPODName returns the name of the SPOD instance we're currently running
// on.
func GetSPODName() string {
	if name := os.Getenv(config.SPOdNameEnvKey); name != "" {
		return name
	}

	return config.SPOdName
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

// LogFilePath returns either the path to the audit logs or falls back to
// syslog if the audit log path does not exist.
func LogFilePath() string {
	filePath := config.SyslogLogPath
	if helpers.Exists(config.AuditLogPath) {
		filePath = config.AuditLogPath
	}

	return filePath
}

func AuditTimeToIso(timestampAuditID string) (string, error) {
	parts := strings.Split(timestampAuditID, ":")
	if len(parts) == 0 {
		return "", fmt.Errorf("invalid timestamp audit ID: %s", timestampAuditID)
	}

	timestampStr := parts[0]

	fractionalParts := strings.Split(timestampStr, ".")
	if len(fractionalParts) == 0 {
		return "", fmt.Errorf("invalid timestamp audit ID: %s", timestampStr)
	}

	seconds, err := strconv.ParseInt(fractionalParts[0], 10, 64)
	if err != nil {
		return "", fmt.Errorf("invalid timestamp audit ID: %s", timestampStr)
	}

	t := time.Unix(seconds, 0).In(time.UTC)

	return t.Format("2006-01-02T15:04:05.000Z"), nil
}
