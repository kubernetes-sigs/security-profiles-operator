module sigs.k8s.io/security-profiles-operator

go 1.15

require (
	github.com/containers/common v0.40.0
	github.com/crossplane/crossplane-runtime v0.14.0
	github.com/go-logr/logr v0.4.0
	github.com/maxbrunsfeld/counterfeiter/v6 v6.4.1
	github.com/pkg/errors v0.9.1
	github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring v0.48.1
	github.com/prometheus/client_golang v1.11.0
	github.com/prometheus/client_model v0.2.0
	github.com/stretchr/testify v1.7.0
	github.com/urfave/cli/v2 v2.3.0
	google.golang.org/grpc v1.38.0
	google.golang.org/grpc/cmd/protoc-gen-go-grpc v1.1.0
	google.golang.org/protobuf v1.26.0
	k8s.io/api v0.20.6
	k8s.io/apimachinery v0.21.1
	k8s.io/client-go v0.20.6
	k8s.io/klog/v2 v2.9.0
	sigs.k8s.io/controller-runtime v0.8.3
	sigs.k8s.io/controller-tools v0.5.0
	sigs.k8s.io/release-utils v0.2.0
	sigs.k8s.io/zeitgeist v0.3.0
)
