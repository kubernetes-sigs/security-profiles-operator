# The catalog of the operator bundle, built from the context that
# `make catalog-context` renders. Unlike the Dockerfile of `opm generate
# dockerfile`, it has no cache that `opm serve --cache-only` pre-built: the
# cache database gets a random seed, which would give every build another
# digest, while the catalog is built reproducibly, see
# doc/release.md#bundle-and-catalog. opm serve builds the cache when it starts
# instead, which takes well below a second for this catalog, and the integrity
# check of a pre-built cache is off, since there is none.
ARG OPM_IMAGE
FROM ${OPM_IMAGE}

ENTRYPOINT ["/bin/opm"]
CMD ["serve", "/configs", "--cache-dir=/tmp/cache", "--cache-enforce-integrity=false"]

COPY configs /configs

# The location of the file-based catalog for OLM.
LABEL operators.operatorframework.io.index.configs.v1=/configs
