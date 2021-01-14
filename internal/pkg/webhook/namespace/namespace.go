// This webhook validates that the pod that's being reviewed is using
// a SELinux policy that exists and is available in the namespace that
// that the pod is being created on.

package namespace

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	spov1alpha1 "sigs.k8s.io/security-profiles-operator/api/selinuxpolicy/v1alpha1"
)

const (
	webhookPort = 8443
	webhookHost = "0.0.0.0"
	webhookPath = "/validate-selinuxpolicy-namespace"
)

var log = logf.Log.WithName("webhook_namespace")

// ValidateNamespace validates that the given pod's selinux policy exists in the namespace
type ValidateNamespace struct {
	client client.Client
	codecs serializer.CodecFactory
}

// Setup creates a new SelinuxPolicy Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Setup(mgr manager.Manager) error {
	// Create a webhook server.
	hookServer := &webhook.Server{
		Host:    webhookHost,
		Port:    webhookPort,
		CertDir: "/webhook-server/serving-certs",
	}
	if err := mgr.Add(hookServer); err != nil {
		return err
	}

	validator := &ValidateNamespace{
		client: mgr.GetClient(),
		codecs: serializer.NewCodecFactory(mgr.GetScheme()),
	}

	validatingHook := &webhook.Admission{
		Handler: admission.HandlerFunc(func(ctx context.Context, req webhook.AdmissionRequest) webhook.AdmissionResponse {
			return validator.Handle(ctx, req)
		}),
	}

	// Register the webhooks in the server.
	hookServer.Register(webhookPath, validatingHook)

	return nil
}

// Handle handles requests for AdmissionRequests
func (v *ValidateNamespace) Handle(ctx context.Context, req webhook.AdmissionRequest) webhook.AdmissionResponse {
	reqLogger := log.WithValues("Request.Namespace", req.Namespace, "Request.Name", req.Name)

	podResource := metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	if req.Resource != podResource {
		reqLogger.Info("Got a request for the wrong resource.")
		return webhook.Errored(500, fmt.Errorf("got a request for the wrong resource"))
	}

	raw := req.Object.Raw
	pod := corev1.Pod{}
	deserializer := v.codecs.UniversalDeserializer()
	if _, _, err := deserializer.Decode(raw, nil, &pod); err != nil {
		reqLogger.Info("ERROR: Unable to decode pod")
		return webhook.Errored(500, fmt.Errorf("got a request but couldn't decode the pod"))
	}

	if req.Operation == admissionv1beta1.Create || req.Operation == admissionv1beta1.Update {
		return v.validateSelinuxNamespace(ctx, reqLogger, &pod)
	}

	return webhook.Allowed("")
}

func (v *ValidateNamespace) validateSelinuxNamespace(ctx context.Context, log logr.Logger, pod *corev1.Pod) webhook.AdmissionResponse {
	secContext := pod.Spec.SecurityContext
	if secContext != nil {
		if valid, response := v.isSelinuxOptionsValidOrNil(ctx, log, secContext.SELinuxOptions, pod.Namespace); !valid {
			return response
		}
	}

	for _, container := range pod.Spec.InitContainers {
		if container.SecurityContext != nil {
			if valid, response := v.isSelinuxOptionsValidOrNil(ctx, log, container.SecurityContext.SELinuxOptions, pod.Namespace); !valid {
				return response
			}
		}
	}
	for _, container := range pod.Spec.Containers {
		if container.SecurityContext != nil {
			if valid, response := v.isSelinuxOptionsValidOrNil(ctx, log, container.SecurityContext.SELinuxOptions, pod.Namespace); !valid {
				return response
			}
		}
	}
	for _, container := range pod.Spec.EphemeralContainers {
		if container.SecurityContext != nil {
			if valid, response := v.isSelinuxOptionsValidOrNil(ctx, log, container.SecurityContext.SELinuxOptions, pod.Namespace); !valid {
				return response
			}
		}
	}
	return webhook.Allowed("")
}

func (v *ValidateNamespace) isSelinuxOptionsValidOrNil(ctx context.Context, log logr.Logger, selinuxOpts *corev1.SELinuxOptions, ns string) (bool, webhook.AdmissionResponse) {
	if selinuxOpts != nil {
		allowed, msg, err := v.isAllowedSelinuxPolicy(ctx, log, selinuxOpts, ns)
		if err != nil {
			return false, webhook.Errored(500, err)
		}
		if !allowed {
			return false, webhook.Denied(msg)
		}
	}
	return true, webhook.AdmissionResponse{}
}

func (v *ValidateNamespace) isAllowedSelinuxPolicy(ctx context.Context, log logr.Logger, selinuxOpts *corev1.SELinuxOptions, ns string) (bool, string, error) {
	// NOTE(jaosorior) Udica generates policies with the ".process" suffix
	// If it's not a udica-provided policy... let's allow it, if
	// it doesn't exist the pod will not be created anyway
	if strings.HasSuffix(selinuxOpts.Type, ".process") && selinuxOpts.Type != ".process" {
		idxWithoutSuffix := len(selinuxOpts.Type) - len(".process")
		return v.isSelinuxPolicyInNamespace(ctx, log, selinuxOpts.Type[:idxWithoutSuffix], ns)
	}
	return true, "", nil
}

func (v *ValidateNamespace) isSelinuxPolicyInNamespace(ctx context.Context, log logr.Logger, policy, ns string) (bool, string, error) {
	policyPieces := strings.Split(policy, "_")
	if len(policyPieces) != 2 {
		msg := fmt.Sprintf("SELinux policy type specification '%s.process' is malformed, the format should be <name>_<namspace>.process", policy)
		return false, msg, nil
	}
	policyName := policyPieces[0]
	policyNamespace := policyPieces[1]
	if policyNamespace != ns {
		msg := fmt.Sprintf("SELinux policy type name not allowed. Cannot access a policy that's not in namespace '%s'", ns)
		return false, msg, nil
	}
	sepolicyNsName := types.NamespacedName{Name: policyName, Namespace: ns}
	instance := &spov1alpha1.SelinuxPolicy{}
	err := v.client.Get(ctx, sepolicyNsName, instance)
	if errors.IsNotFound(err) {
		msg := fmt.Sprintf("SelinuxPolicy '%s' is not in namespace '%s'", policy, ns)
		return false, msg, nil
	}
	if err != nil {
		return false, "", err
	}
	return true, "", nil
}
