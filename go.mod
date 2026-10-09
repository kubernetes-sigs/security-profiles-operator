module sigs.k8s.io/security-profiles-operator

go 1.27.0

toolchain go1.27.2

require (
	cloud.google.com/go/compute/metadata v0.10.0
	github.com/aquasecurity/libbpfgo v0.11.0-libbpf-1.8-dev-2bbc483
	github.com/blang/semver/v4 v4.0.0
	github.com/cert-manager/cert-manager v1.21.2
	github.com/evanphx/json-patch/v5 v5.9.11
	github.com/fsnotify/fsnotify v1.10.1
	github.com/go-logr/logr v1.4.4
	github.com/google/cel-go v0.30.0
	github.com/google/go-cmp v0.7.0
	github.com/google/go-containerregistry v0.22.1
	github.com/google/uuid v1.6.0
	github.com/hairyhenderson/go-which v0.2.3
	github.com/in-toto/attestation v1.2.0
	github.com/jellydator/ttlcache/v3 v3.4.1
	github.com/moby/sys/mountinfo v0.7.2
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.1.1
	github.com/opencontainers/runc v1.5.2
	github.com/opencontainers/runtime-spec v1.3.0
	github.com/openshift/api v0.0.0-20260507162658-047c8957c266
	github.com/openshift/controller-runtime-common v0.0.0-20260428152732-64ee174f5e2e
	github.com/openshift/library-go v0.0.0-20260511114641-ae196b55736d
	github.com/pjbgf/go-apparmor v0.1.3
	github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring v0.94.1
	github.com/prometheus/client_golang v1.24.1
	github.com/prometheus/client_model v0.6.3
	github.com/seccomp/libseccomp-golang v0.12.0
	github.com/sigstore/protobuf-specs v0.5.2
	github.com/sigstore/rekor v1.5.4
	github.com/sigstore/sigstore v1.11.0
	github.com/sigstore/sigstore-go v1.3.0
	github.com/stretchr/testify v1.12.1
	github.com/urfave/cli/v2 v2.27.7
	go.podman.io/common v0.69.2
	golang.org/x/mod v0.41.0
	golang.org/x/sync v0.24.0
	golang.org/x/sys v0.48.0
	golang.org/x/term v0.46.0
	gomodules.xyz/jsonpatch/v2 v2.5.0
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.12
	gopkg.in/natefinch/lumberjack.v2 v2.2.1
	k8s.io/api v0.37.1
	k8s.io/apimachinery v0.37.1
	k8s.io/apiserver v0.37.1
	k8s.io/cli-runtime v0.37.1
	k8s.io/client-go v0.37.1
	k8s.io/klog/v2 v2.140.0
	k8s.io/utils v0.0.0-20260707023825-cf1189d6abe3
	oras.land/oras-go/v2 v2.6.2
	sigs.k8s.io/controller-runtime v0.25.2
	sigs.k8s.io/release-utils v0.12.5
	sigs.k8s.io/security-profiles-merger v0.7.0
	sigs.k8s.io/yaml v1.6.0
)

require (
	al.essio.dev/pkg/shellescape v1.6.0 // indirect
	cel.dev/expr v0.25.2 // indirect
	cyphar.com/go-pathrs v0.2.6 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20250102033503-faa5f7b0171c // indirect
	github.com/ProtonMail/go-crypto v1.4.1 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/clipperhouse/displaywidth v0.11.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/coreos/go-oidc/v3 v3.20.0 // indirect
	github.com/coreos/go-systemd/v22 v22.7.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.7 // indirect
	github.com/creack/pty v1.1.24 // indirect
	github.com/cyberphone/json-canonicalization v0.0.0-20241213102144-19d51d7fe467 // indirect
	github.com/cyphar/filepath-securejoin v0.7.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/digitorus/pkcs7 v0.0.0-20250730155240-ffadbf3f398c // indirect
	github.com/digitorus/timestamp v0.0.0-20231217203849-220c5c2851b7 // indirect
	github.com/docker/cli v29.7.2+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.9.8 // indirect
	github.com/emicklei/go-restful/v3 v3.13.0 // indirect
	github.com/fatih/color v1.19.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fxamacker/cbor/v2 v2.9.3 // indirect
	github.com/go-jose/go-jose/v4 v4.1.5 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-openapi/analysis v0.26.0 // indirect
	github.com/go-openapi/errors v0.22.8 // indirect
	github.com/go-openapi/jsonpointer v1.0.0 // indirect
	github.com/go-openapi/jsonreference v1.0.0 // indirect
	github.com/go-openapi/loads v0.25.1 // indirect
	github.com/go-openapi/runtime v0.33.0 // indirect
	github.com/go-openapi/runtime/server-middleware v0.30.0 // indirect
	github.com/go-openapi/spec v0.22.9 // indirect
	github.com/go-openapi/strfmt v0.27.0 // indirect
	github.com/go-openapi/swag v0.27.1 // indirect
	github.com/go-openapi/swag/cmdutils v0.27.1 // indirect
	github.com/go-openapi/swag/conv v0.28.0 // indirect
	github.com/go-openapi/swag/fileutils v0.28.0 // indirect
	github.com/go-openapi/swag/jsonutils v0.28.0 // indirect
	github.com/go-openapi/swag/loading v0.28.0 // indirect
	github.com/go-openapi/swag/mangling v0.28.0 // indirect
	github.com/go-openapi/swag/netutils v0.27.1 // indirect
	github.com/go-openapi/swag/pools v0.28.0 // indirect
	github.com/go-openapi/swag/stringutils v0.28.0 // indirect
	github.com/go-openapi/swag/typeutils v0.28.0 // indirect
	github.com/go-openapi/swag/yamlutils v0.28.0 // indirect
	github.com/go-openapi/validate v0.26.3 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/gobuffalo/flect v1.0.3 // indirect
	github.com/goccy/go-json v0.10.6 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/google/certificate-transparency-go v1.3.3 // indirect
	github.com/google/gnostic-models v0.7.1 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.29.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.8 // indirect
	github.com/in-toto/in-toto-golang v0.11.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jedisct1/go-minisign v0.0.0-20241212093149-d2f9f49435c7 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/compress v1.19.2 // indirect
	github.com/liggitt/tabwriter v0.0.0-20181228230101-89fcab3d43de // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.27 // indirect
	github.com/maxbrunsfeld/counterfeiter/v6 v6.14.0 // indirect
	github.com/mitchellh/mapstructure v1.5.1-0.20231216201459-8508981c8b6c // indirect
	github.com/moby/sys/userns v0.2.1 // indirect
	github.com/moby/term v0.5.2 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/mogensen/kubernetes-split-yaml v0.4.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/oklog/ulid/v2 v2.1.1 // indirect
	github.com/olekukonko/cat v0.0.0-20250911104152-50322a0618f6 // indirect
	github.com/olekukonko/errors v1.2.0 // indirect
	github.com/olekukonko/ll v0.1.7 // indirect
	github.com/olekukonko/tablewriter v1.1.5 // indirect
	github.com/opencontainers/cgroups v0.1.0 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/common v0.70.1 // indirect
	github.com/prometheus/procfs v0.21.1 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/sassoftware/relic/v8 v8.2.0 // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.11.1 // indirect
	github.com/shibumi/go-pathspec v1.3.0 // indirect
	github.com/sigstore/rekor-tiles/v2 v2.3.0 // indirect
	github.com/sigstore/timestamp-authority/v2 v2.1.3 // indirect
	github.com/sirupsen/logrus v1.10.2 // indirect
	github.com/spf13/cobra v1.10.2 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/theupdateframework/go-tuf v0.7.0 // indirect
	github.com/theupdateframework/go-tuf/v2 v2.4.2 // indirect
	github.com/transparency-dev/formats v0.1.1 // indirect
	github.com/transparency-dev/merkle v0.0.2 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xrash/smetrics v0.0.0-20250705151800-55b8f293f342 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.69.0 // indirect
	go.opentelemetry.io/otel v1.45.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.45.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.45.0 // indirect
	go.opentelemetry.io/otel/metric v1.45.0 // indirect
	go.opentelemetry.io/otel/sdk v1.45.0 // indirect
	go.opentelemetry.io/otel/trace v1.45.0 // indirect
	go.opentelemetry.io/proto/otlp v1.11.0 // indirect
	go.yaml.in/yaml/v2 v2.4.4 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/exp v0.0.0-20260410095643-746e56fc9e2f // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	golang.org/x/tools v0.50.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260803160001-6ac0973c030d // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260803160001-6ac0973c030d // indirect
	google.golang.org/grpc/cmd/protoc-gen-go-grpc v1.6.2 // indirect
	gopkg.in/evanphx/json-patch.v4 v4.13.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gotest.tools/v3 v3.5.2 // indirect
	k8s.io/apiextensions-apiserver v0.37.0 // indirect
	k8s.io/code-generator v0.37.0 // indirect
	k8s.io/component-base v0.37.1 // indirect
	k8s.io/gengo/v2 v2.0.0-20260408192533-25e2208e0dc3 // indirect
	k8s.io/kube-openapi v0.0.0-20260821135717-be32def86098 // indirect
	k8s.io/streaming v0.37.1 // indirect
	sigs.k8s.io/apiserver-network-proxy/konnectivity-client v0.36.0 // indirect
	sigs.k8s.io/controller-tools v0.22.0 // indirect
	sigs.k8s.io/gateway-api v1.6.0 // indirect
	sigs.k8s.io/json v0.0.0-20250730193827-2d320260d730 // indirect
	sigs.k8s.io/randfill v1.0.0 // indirect
	sigs.k8s.io/structured-merge-diff/v6 v6.4.2 // indirect
)

tool (
	github.com/maxbrunsfeld/counterfeiter/v6
	github.com/mogensen/kubernetes-split-yaml
	google.golang.org/grpc/cmd/protoc-gen-go-grpc
	google.golang.org/protobuf/cmd/protoc-gen-go
	sigs.k8s.io/controller-tools/cmd/controller-gen
)
