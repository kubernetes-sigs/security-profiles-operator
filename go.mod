module sigs.k8s.io/seccomp-operator

go 1.14

require (
	github.com/crossplane/crossplane-runtime v0.9.0
	github.com/go-logr/logr v0.2.1-0.20200730175230-ee2de8da5be6 // TODO: switch to v0.2.1 if released
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.6.1
	github.com/urfave/cli/v2 v2.2.0
	k8s.io/api v0.18.6
	k8s.io/apimachinery v0.18.6
	k8s.io/klog/v2 v2.3.0
	k8s.io/release v0.3.4
	sigs.k8s.io/controller-runtime v0.6.2
)
