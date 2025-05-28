
FROM brew.registry.redhat.io/rh-osbs/openshift-golang-builder:v1.23 as builder-runner
# Use a new stage to enable caching of the package installations for local development
FROM builder-runner as builder
ARG SPO_VERSION="0.9.0"
COPY . .
WORKDIR bundle-hack
RUN go run ./update_csv.go ../bundle/manifests ${SPO_VERSION}
RUN ./update_bundle_annotations.sh
RUN ./update_bundle_namespace.sh
RUN ./update_bundle_rbac.sh

FROM scratch
LABEL name=openshift-compliance-operator-bundle
LABEL version=${SPO_VERSION}
LABEL summary='OpenShift Security Profiles Operator'
LABEL maintainer='Infrastructure Security and Compliance Team <isc-team@redhat.com>'
LABEL io.k8s.display-name='Security Profiles Operator'
LABEL io.k8s.description='OpenShift Security Profiles Operator'
LABEL com.redhat.component=security-profiles-operator-bundle-container
LABEL com.redhat.delivery.appregistry=false
LABEL com.redhat.delivery.operator.bundle=true
LABEL com.redhat.openshift.versions="v4.12"
LABEL io.openshift.maintainer.product='OpenShift Container Platform'
LABEL io.openshift.tags=openshift,security,selinux,seccomp
LABEL operators.operatorframework.io.bundle.channel.default.v1=release-alpha-rhel-8
LABEL operators.operatorframework.io.bundle.channels.v1=release-alpha-rhel-8
LABEL operators.operatorframework.io.bundle.manifests.v1=manifests/
LABEL operators.operatorframework.io.bundle.mediatype.v1=registry+v1
LABEL operators.operatorframework.io.bundle.metadata.v1=metadata/
LABEL operators.operatorframework.io.bundle.package.v1=security-profiles-operator
LABEL License=Apache
# Copy files to locations specified by labels.
COPY --from=builder bundle/manifests /manifests/
COPY --from=builder bundle/metadata /metadata/
COPY bundle/tests/scorecard /tests/scorecard
