module sigs.k8s.io/security-profiles-operator

go 1.15

require (
	github.com/ReneKroon/ttlcache/v2 v2.7.0
	github.com/containers/common v0.41.0
	github.com/crossplane/crossplane-runtime v0.14.0
	github.com/go-logr/logr v0.4.0
	github.com/maxbrunsfeld/counterfeiter/v6 v6.4.1
	github.com/nxadm/tail v1.4.8
	github.com/pkg/errors v0.9.1
	github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring v0.49.0
	github.com/prometheus/client_golang v1.11.0
	github.com/prometheus/client_model v0.2.0
	github.com/seccomp/libseccomp-golang v0.9.2-0.20200616122406-847368b35ebf
	github.com/stretchr/testify v1.7.0
	github.com/urfave/cli/v2 v2.3.0
	google.golang.org/grpc v1.39.0
	google.golang.org/grpc/cmd/protoc-gen-go-grpc v1.1.0
	google.golang.org/protobuf v1.27.1
	k8s.io/api v0.21.2
	k8s.io/apimachinery v0.21.3
	k8s.io/client-go v0.21.2
	k8s.io/klog/v2 v2.10.0
	sigs.k8s.io/controller-runtime v0.9.3
	sigs.k8s.io/controller-tools v0.5.0
	sigs.k8s.io/mdtoc v1.0.1
	sigs.k8s.io/release-utils v0.3.0
	sigs.k8s.io/zeitgeist v0.3.0
)
