module github.com/kubernetes-sigs/seccomp-operator

go 1.14

require (
	github.com/crossplane/crossplane-runtime v0.9.0
	github.com/go-logr/logr v0.1.0
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.6.1
	github.com/urfave/cli/v2 v2.2.0
	k8s.io/api v0.18.5
	k8s.io/apimachinery v0.18.5
	k8s.io/klog v1.0.0
	k8s.io/release v0.3.4
	sigs.k8s.io/controller-runtime v0.6.1
)
