/*
Copyright 2022 The Kubernetes Authors.

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

package bindata

import (
	"context"
	"fmt"
	"strings"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	certmanagermetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/go-logr/logr"
	configv1 "github.com/openshift/api/config/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

type CAInjectType uint

const (
	// CAInjectTypeCertManager can be used to rely on Cert Manager for CA
	// injection.
	CAInjectTypeCertManager CAInjectType = 0

	// CAInjectTypeOpenShift can be used in OpenShift environments.
	CAInjectTypeOpenShift CAInjectType = 1
)

func GetCAInjectType(
	ctx context.Context, log logr.Logger, c client.Client,
) (res CAInjectType, err error) {
	err = c.Get(ctx,
		types.NamespacedName{Name: "openshift-apiserver"},
		&configv1.ClusterOperator{},
	)
	if err == nil {
		log.Info("Using OpenShift as certificate provider")
		return CAInjectTypeOpenShift, nil
	}
	if meta.IsNoMatchError(err) ||
		// for the namespaced operator
		strings.Contains(err.Error(), "failed to get restmapping") {
		log.Info("Using cert-manager as certificate provider")
		return CAInjectTypeCertManager, nil
	}

	return res, fmt.Errorf("unable to determine certificate provider: %w", err)
}

const (
	issuerName = "selfsigned-issuer"
)

type CertManagerResources struct {
	issuer      *certmanagerv1.Issuer
	metricsCert *certmanagerv1.Certificate
	webhookCert *certmanagerv1.Certificate
}

func GetCertManagerResources(namespace string) *CertManagerResources {
	i := issuer.DeepCopy()
	i.Namespace = namespace

	mc := metricsCert.DeepCopy()
	mc.Namespace = namespace

	wc := webhookCert.DeepCopy()
	wc.Namespace = namespace

	return &CertManagerResources{
		issuer:      i,
		metricsCert: mc,
		webhookCert: wc,
	}
}

func (c *CertManagerResources) Create(ctx context.Context, cl client.Client) error {
	for k, o := range c.objectMap() {
		if err := cl.Create(ctx, o); err != nil {
			if errors.IsAlreadyExists(err) {
				continue
			}
			return fmt.Errorf("creating %s: %w", k, err)
		}
	}
	return nil
}

func (c *CertManagerResources) Update(ctx context.Context, cl client.Client) error {
	for k, o := range c.objectMap() {
		if err := cl.Patch(ctx, o, client.Merge); err != nil {
			return fmt.Errorf("updating %s: %w", k, err)
		}
	}
	return nil
}

func (c *CertManagerResources) objectMap() map[string]client.Object {
	return map[string]client.Object{
		"issuer":       c.issuer,
		"metrics cert": c.metricsCert,
		"webhook cert": c.webhookCert,
	}
}

var issuer = certmanagerv1.Issuer{
	ObjectMeta: metav1.ObjectMeta{
		Name: issuerName,
		Labels: map[string]string{
			"app": config.OperatorName,
		},
	},
	Spec: certmanagerv1.IssuerSpec{
		IssuerConfig: certmanagerv1.IssuerConfig{
			SelfSigned: &certmanagerv1.SelfSignedIssuer{},
		},
	},
}

var metricsCert = certmanagerv1.Certificate{
	ObjectMeta: metav1.ObjectMeta{
		Name: "metrics-cert",
		Labels: map[string]string{
			"app": config.OperatorName,
		},
	},
	Spec: certmanagerv1.CertificateSpec{
		IssuerRef: certmanagermetav1.ObjectReference{
			Name: issuerName,
			Kind: "Issuer",
		},
		SecretName: metricsServerCert,
		DNSNames: []string{
			"metrics.security-profiles-operator",
			"metrics.security-profiles-operator.svc",
			"metrics.security-profiles-operator.svc.cluster.local",
		},
		Subject: &certmanagerv1.X509Subject{
			Organizations: []string{config.OperatorName},
		},
	},
}

var webhookCert = certmanagerv1.Certificate{
	ObjectMeta: metav1.ObjectMeta{
		Name: "webhook-cert",
		Labels: map[string]string{
			"app": config.OperatorName,
		},
	},
	Spec: certmanagerv1.CertificateSpec{
		IssuerRef: certmanagermetav1.ObjectReference{
			Name: issuerName,
			Kind: "Issuer",
		},
		SecretName: webhookServerCert,
		DNSNames: []string{
			"webhook-service.security-profiles-operator.svc",
			"webhook-service.security-profiles-operator.svc.cluster.local",
		},
	},
}
