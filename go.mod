module sigs.k8s.io/security-profiles-operator

go 1.15

require (
	github.com/ReneKroon/ttlcache/v2 v2.9.0
	github.com/acobaugh/osrelease v0.0.0-20181218015638-a93a0a55a249
	github.com/aquasecurity/libbpfgo v0.2.1-libbpf-0.4.0.0.20210928164917-f097a0171b12
	github.com/containers/common v0.46.0
	github.com/crossplane/crossplane-runtime v0.14.1-0.20210713194031-85b19c28ea88
	github.com/go-logr/logr v1.2.0
	github.com/maxbrunsfeld/counterfeiter/v6 v6.4.1
	github.com/nxadm/tail v1.4.8
	github.com/pjbgf/go-apparmor v0.0.7
	github.com/pkg/errors v0.9.1
	github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring v0.52.0
	github.com/prometheus/client_golang v1.11.0
	github.com/prometheus/client_model v0.2.0
	github.com/seccomp/libseccomp-golang v0.9.2-0.20200616122406-847368b35ebf
	github.com/stretchr/testify v1.7.0
	github.com/urfave/cli/v2 v2.3.0
	golang.org/x/sys v0.0.0-20211116061358-0a5406a5449c // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/grpc v1.42.0
	google.golang.org/grpc/cmd/protoc-gen-go-grpc v1.1.0
	google.golang.org/protobuf v1.27.1
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	k8s.io/api v0.22.4
	k8s.io/apimachinery v0.22.4
	k8s.io/client-go v0.22.4
	k8s.io/klog/v2 v2.10.0
	sigs.k8s.io/controller-runtime v0.10.3
	sigs.k8s.io/controller-tools v0.7.0
	sigs.k8s.io/mdtoc v1.1.0
	sigs.k8s.io/release-utils v0.3.0
	sigs.k8s.io/zeitgeist v0.3.0
)
