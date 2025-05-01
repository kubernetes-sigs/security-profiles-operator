# The base version determines the index that the build will be included in, but
# not exactly. It is based on semantics of
# https://docs.engineering.redhat.com/display/CFC/Delivery
# 4.10 means that we will be included in 4.10+ indexes
BASE_OCP_VERSION="4.10"
# We use the stable channel because the Compliance Operator adheres to Tier
# 3 operator lifecycle management
# https://docs.google.com/document/d/18BPe68jhk16-4eYGT6zV-iSNLrFVsuPdVIos24kWaaE/edit
CHANNEL="stable"
ANNOTATIONS_CONTENT=$(cat << EOM
annotations:
  com.redhat.openshift.versions: "v${BASE_OCP_VERSION}"
  operators.operatorframework.io.bundle.channel.default.v1: '${CHANNEL}'
  operators.operatorframework.io.bundle.channels.v1: '${CHANNEL}'
  operators.operatorframework.io.bundle.manifests.v1: manifests/
  operators.operatorframework.io.bundle.mediatype.v1: registry+v1
  operators.operatorframework.io.bundle.metadata.v1: metadata/
  operators.operatorframework.io.bundle.package.v1: compliance-operator
EOM
)
echo "$ANNOTATIONS_CONTENT" > ../bundle/metadata/annotations.yaml