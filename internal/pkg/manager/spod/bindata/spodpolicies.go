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

package bindata

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"
	"io/fs"
	"strconv"
	"sync"
	"time"

	admissionregv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	yamlutil "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

// spodPolicyFiles are copies of the spod_*_policy.yaml files of deploy/base,
// which TestSpodAdmissionPoliciesMatchDeployment keeps in sync.
//
//go:embed admissionpolicies/*.yaml
var spodPolicyFiles embed.FS

// SpodAdmissionPolicyNames are the names of the ValidatingAdmissionPolicies,
// and of their bindings, which restrict the writes of the spod service
// account, see SpodAdmissionPolicies.
var SpodAdmissionPolicyNames = []string{
	"spo-spod-jobs",
	"spo-spod-node-statuses",
	"spo-spod-profiles",
	"spo-spod-recordings",
}

// spodPolicyHashAnnotation is set on the spod admission policies created by
// the operator. Its value is the hash of the spec they got created or updated
// with.
const spodPolicyHashAnnotation = "spo.x-k8s.io/admission-policy-hash"

// spodServiceAccountCondition is the name of the match condition of the spod
// admission policies which selects the requests of the spod service account.
const spodServiceAccountCondition = "spod-service-account"

var (
	errUnexpectedPolicyKind  = stderrors.New("unexpected kind")
	errNoServiceAccountMatch = stderrors.New(
		"no " + spodServiceAccountCondition + " match condition",
	)
)

// SpodPolicyResync is the time after which Apply checks the policies again,
// although it applied them successfully, see SpodAdmissionPolicies.
const SpodPolicyResync = 10 * time.Minute

// SpodAdmissionPolicies are the ValidatingAdmissionPolicies and bindings
// which restrict the writes of the spod service account to the objects of
// its own node. The kustomize and Helm deployments ship them, OLM bundles
// cannot, so the operator creates them if they are missing. Only the policies
// created by the operator, which carry spodPolicyHashAnnotation, get updated
// by it, when their spec changes with a new release. The ones of the
// deployments are left to them. The deployments do not know the operator
// namespace, so their policies select the service accounts named spod of all
// namespaces. The operator narrows the ones it creates to the spod service
// account of its namespace.
//
// The policies are not cached, so every check reads each of them from the
// API server. The SPOD gets reconciled on every status change of its
// operands, so Apply only checks them again SpodPolicyResync after it applied
// them successfully. The SPOD controller reconciles again after that time.
// The trade-off is that a deleted policy only gets created again up to
// SpodPolicyResync later.
type SpodAdmissionPolicies struct {
	objects []client.Object

	// mu guards appliedAt, the time of the last successful Apply, which is
	// zero after a failed one.
	mu        sync.Mutex
	appliedAt time.Time
	now       func() time.Time
}

// GetSpodAdmissionPolicies returns the spod admission policies for the
// operator namespace.
func GetSpodAdmissionPolicies(operatorNamespace string) (*SpodAdmissionPolicies, error) {
	parsed, err := parseSpodPolicies()
	if err != nil {
		return nil, err
	}

	objects := make([]client.Object, 0, len(parsed))

	for _, obj := range parsed {
		var spec any

		switch o := obj.DeepCopyObject().(type) {
		case *admissionregv1.ValidatingAdmissionPolicy:
			if !inNamespace(o, operatorNamespace) {
				return nil, fmt.Errorf("%w: %s", errNoServiceAccountMatch, o.Name)
			}

			obj, spec = o, &o.Spec
		case *admissionregv1.ValidatingAdmissionPolicyBinding:
			obj, spec = o, &o.Spec
		default:
			return nil, fmt.Errorf("%w %T", errUnexpectedPolicyKind, o)
		}

		specJSON, err := json.Marshal(spec)
		if err != nil {
			return nil, fmt.Errorf("marshal spec of %s: %w", obj.GetName(), err)
		}

		hash := sha256.Sum256(specJSON)

		obj.SetLabels(map[string]string{labelApp: config.OperatorName})
		obj.SetAnnotations(map[string]string{spodPolicyHashAnnotation: hex.EncodeToString(hash[:])})

		objects = append(objects, obj)
	}

	return &SpodAdmissionPolicies{objects: objects, now: time.Now}, nil
}

// inNamespace narrows the spod service account match condition of the policy
// to the service account of the namespace. It returns false if the policy
// has no such condition.
func inNamespace(policy *admissionregv1.ValidatingAdmissionPolicy, namespace string) bool {
	for i := range policy.Spec.MatchConditions {
		condition := &policy.Spec.MatchConditions[i]
		if condition.Name != spodServiceAccountCondition {
			continue
		}

		condition.Expression = "request.userInfo.username == " +
			strconv.Quote("system:serviceaccount:"+namespace+":spod")

		return true
	}

	return false
}

// parseSpodPolicies parses the embedded policies once.
var parseSpodPolicies = sync.OnceValues(func() ([]client.Object, error) {
	var objects []client.Object

	err := fs.WalkDir(spodPolicyFiles, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}

		content, err := spodPolicyFiles.ReadFile(name)
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}

		parsed, err := parsePolicyDocuments(content)
		if err != nil {
			return fmt.Errorf("parse %s: %w", name, err)
		}

		objects = append(objects, parsed...)

		return nil
	})

	return objects, err
})

// parsePolicyDocuments parses the YAML documents into admission policies and
// their bindings.
func parsePolicyDocuments(content []byte) ([]client.Object, error) {
	var objects []client.Object

	reader := yamlutil.NewYAMLReader(bufio.NewReader(bytes.NewReader(content)))

	for {
		doc, err := reader.Read()
		if stderrors.Is(err, io.EOF) {
			return objects, nil
		}

		if err != nil {
			return nil, fmt.Errorf("read document: %w", err)
		}

		typeMeta := metav1.TypeMeta{}
		if err := yaml.Unmarshal(doc, &typeMeta); err != nil {
			return nil, fmt.Errorf("unmarshal type: %w", err)
		}

		var obj client.Object

		switch typeMeta.Kind {
		case "":
			// A document without content, like the one before a leading
			// separator.
			continue
		case "ValidatingAdmissionPolicy":
			obj = &admissionregv1.ValidatingAdmissionPolicy{}
		case "ValidatingAdmissionPolicyBinding":
			obj = &admissionregv1.ValidatingAdmissionPolicyBinding{}
		default:
			return nil, fmt.Errorf("%w %q", errUnexpectedPolicyKind, typeMeta.Kind)
		}

		if err := yaml.UnmarshalStrict(doc, obj); err != nil {
			return nil, fmt.Errorf("unmarshal %s: %w", typeMeta.Kind, err)
		}

		objects = append(objects, obj)
	}
}

// Apply creates the policies and bindings which do not exist, and updates the
// ones created by the operator whose spec changed, unless it did so less than
// SpodPolicyResync ago. The objects are read through the uncached reader, the
// cache of the operator only holds the recording profiles policy. The
// returned errors wrap the ones of the client, so IsNotFound matches them if
// the cluster does not serve the ValidatingAdmissionPolicy API, or if an
// object got deleted between its read and its update.
func (p *SpodAdmissionPolicies) Apply(
	ctx context.Context, c client.Client, reader client.Reader,
) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.appliedAt.IsZero() && p.now().Sub(p.appliedAt) < SpodPolicyResync {
		return nil
	}

	p.appliedAt = time.Time{}

	if err := p.apply(ctx, c, reader); err != nil {
		return err
	}

	p.appliedAt = p.now()

	return nil
}

// apply checks every policy and binding, see Apply.
func (p *SpodAdmissionPolicies) apply(
	ctx context.Context, c client.Client, reader client.Reader,
) error {
	for _, desired := range p.objects {
		existing, ok := desired.DeepCopyObject().(client.Object)
		if !ok {
			return fmt.Errorf("copy %T: %w", desired, errNotAnObject)
		}

		if err := reader.Get(ctx, client.ObjectKeyFromObject(desired), existing); err != nil {
			if !errors.IsNotFound(err) {
				return fmt.Errorf("get %T %s: %w", desired, desired.GetName(), err)
			}

			obj, ok := desired.DeepCopyObject().(client.Object)
			if !ok {
				return fmt.Errorf("copy %T: %w", desired, errNotAnObject)
			}

			if err := c.Create(ctx, obj); err != nil && !errors.IsAlreadyExists(err) {
				return fmt.Errorf("create %T %s: %w", obj, obj.GetName(), err)
			}

			continue
		}

		hash, created := existing.GetAnnotations()[spodPolicyHashAnnotation]
		if !created || hash == desired.GetAnnotations()[spodPolicyHashAnnotation] {
			continue
		}

		switch d := desired.(type) {
		case *admissionregv1.ValidatingAdmissionPolicy:
			e, ok := existing.(*admissionregv1.ValidatingAdmissionPolicy)
			if ok {
				e.Spec = *d.Spec.DeepCopy()
			}
		case *admissionregv1.ValidatingAdmissionPolicyBinding:
			e, ok := existing.(*admissionregv1.ValidatingAdmissionPolicyBinding)
			if ok {
				e.Spec = *d.Spec.DeepCopy()
			}
		}

		annotations := existing.GetAnnotations()
		annotations[spodPolicyHashAnnotation] = desired.GetAnnotations()[spodPolicyHashAnnotation]
		existing.SetAnnotations(annotations)

		// The update uses the fetched resource version, so it fails on a
		// concurrent change and gets retried by the next reconciliation.
		if err := c.Update(ctx, existing); err != nil {
			return fmt.Errorf("update %T %s: %w", existing, existing.GetName(), err)
		}
	}

	return nil
}
