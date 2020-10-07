module sigs.k8s.io/security-profiles-operator

go 1.15

require (
	github.com/containers/common v0.21.0 // can be built with the `seccomp` build tag to support more features
	github.com/crossplane/crossplane-runtime v0.9.0
	github.com/go-logr/logr v0.2.1
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.6.1
	github.com/urfave/cli/v2 v2.2.0
	k8s.io/api v0.19.2
	k8s.io/apimachinery v0.19.2
	k8s.io/klog/v2 v2.3.0
	k8s.io/release v0.4.1
	sigs.k8s.io/controller-runtime v0.6.3
)
