module sigs.k8s.io/security-profiles-operator

go 1.15

require (
	github.com/ReneKroon/ttlcache/v2 v2.11.0
	github.com/acobaugh/osrelease v0.0.0-20181218015638-a93a0a55a249
	github.com/aquasecurity/libbpfgo v0.2.5-libbpf-0.7.0
	github.com/containers/common v0.47.4
	github.com/crossplane/crossplane-runtime v0.14.1-0.20210713194031-85b19c28ea88
	github.com/go-logr/logr v1.2.3
	github.com/jetstack/cert-manager v1.7.1
	github.com/maxbrunsfeld/counterfeiter/v6 v6.5.0
	github.com/nxadm/tail v1.4.8
	github.com/openshift/api v0.0.0-20220209124712-b632c5fc10c0
	github.com/pjbgf/go-apparmor v0.0.7
	github.com/pkg/errors v0.9.1
	github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring v0.55.0
	github.com/prometheus/client_golang v1.12.1
	github.com/prometheus/client_model v0.2.0
	github.com/seccomp/libseccomp-golang v0.9.2-0.20210429002308-3879420cc921
	github.com/stretchr/testify v1.7.1
	github.com/urfave/cli/v2 v2.4.0
	google.golang.org/grpc v1.45.0
	google.golang.org/grpc/cmd/protoc-gen-go-grpc v1.2.0
	google.golang.org/protobuf v1.27.1
	k8s.io/api v0.23.5
	k8s.io/apimachinery v0.23.5
	k8s.io/client-go v0.23.5
	k8s.io/klog/v2 v2.60.0
	sigs.k8s.io/controller-runtime v0.11.1
	sigs.k8s.io/controller-tools v0.8.0
	sigs.k8s.io/mdtoc v1.1.0
	sigs.k8s.io/release-utils v0.5.0
	sigs.k8s.io/zeitgeist v0.3.0
)
