module sigs.k8s.io/seccomp-operator

go 1.15

require (
	github.com/containers/common v0.20.3-0.20200827091701-a550d6a98aa3 // can be built with the `seccomp` build tag to support more features
	github.com/crossplane/crossplane-runtime v0.9.0
	github.com/go-logr/logr v0.2.1-0.20200730175230-ee2de8da5be6 // TODO: switch to v0.2.1 if released
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.6.1
	github.com/urfave/cli/v2 v2.2.0
	golang.org/x/sys v0.0.0-20200806125547-5acd03effb82
	k8s.io/api v0.18.6
	k8s.io/apimachinery v0.18.6
	k8s.io/klog/v2 v2.3.0
	k8s.io/release v0.4.0
	sigs.k8s.io/controller-runtime v0.6.2
)
