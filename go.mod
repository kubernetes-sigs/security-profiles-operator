module sigs.k8s.io/security-profiles-operator

go 1.15

require (
	github.com/containers/common v0.35.2
	github.com/crossplane/crossplane-runtime v0.13.0
	github.com/go-logr/logr v0.4.0
	github.com/maxbrunsfeld/counterfeiter/v6 v6.3.0
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.0
	github.com/urfave/cli/v2 v2.3.0
	k8s.io/api v0.20.4
	k8s.io/apimachinery v0.20.4
	k8s.io/client-go v0.20.4
	k8s.io/klog/v2 v2.5.0
	k8s.io/release v0.7.0
	sigs.k8s.io/controller-runtime v0.8.2
	sigs.k8s.io/controller-tools v0.5.0
)
