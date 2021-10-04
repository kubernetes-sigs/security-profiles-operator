module sigs.k8s.io/security-profiles-operator

go 1.15

require (
	github.com/ReneKroon/ttlcache/v2 v2.8.1
	github.com/containers/common v0.43.2
	github.com/crossplane/crossplane-runtime v0.14.1-0.20210713194031-85b19c28ea88
	github.com/go-logr/logr v0.4.0
	github.com/maxbrunsfeld/counterfeiter/v6 v6.4.1
	github.com/nxadm/tail v1.4.8
	github.com/pkg/errors v0.9.1
	github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring v0.50.0
	github.com/prometheus/client_golang v1.11.0
	github.com/prometheus/client_model v0.2.0
	github.com/seccomp/libseccomp-golang v0.9.2-0.20200616122406-847368b35ebf
	github.com/stretchr/testify v1.7.0
	github.com/urfave/cli/v2 v2.3.0
	google.golang.org/grpc v1.41.0
	google.golang.org/grpc/cmd/protoc-gen-go-grpc v1.1.0
	google.golang.org/protobuf v1.27.1
	k8s.io/api v0.22.2
	k8s.io/apimachinery v0.22.2
	k8s.io/client-go v0.22.2
	k8s.io/klog/v2 v2.10.0
	sigs.k8s.io/controller-runtime v0.10.1
	sigs.k8s.io/controller-tools v0.6.2
	sigs.k8s.io/mdtoc v1.0.1
	sigs.k8s.io/release-utils v0.3.0
	sigs.k8s.io/zeitgeist v0.3.0
)
