FROM hairyhenderson/upx:3.96 AS upx

FROM golang:1.14.6-alpine AS build

RUN apk add --no-cache \
    make \
    libgcc libstdc++ ucl \
    git

COPY --from=upx /usr/bin/upx /usr/bin/upx

RUN mkdir -p /go/src/github.com/hairyhenderson/go-which
WORKDIR /go/src/github.com/hairyhenderson/go-which
COPY . /go/src/github.com/hairyhenderson/go-which

ARG VCS_REF
ARG VERSION
ARG CODEOWNERS

RUN make build-x

FROM build AS compress

RUN make compress-all

FROM scratch AS artifacts

COPY --from=compress /go/src/github.com/hairyhenderson/go-which/bin/* /bin/

FROM scratch AS latest

ARG OS=linux
ARG ARCH=amd64

COPY --from=build /go/src/github.com/hairyhenderson/go-which/bin/which_${OS}-${ARCH} /which

ARG VCS_REF
ARG VERSION
ARG CODEOWNERS

LABEL org.opencontainers.image.revision=$VCS_REF \
      org.opencontainers.image.title=go-which \
      org.opencontainers.image.authors=$CODEOWNERS \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.source="https://github.com/hairyhenderson/go-which"

ENTRYPOINT [ "/which" ]

FROM alpine:3.12.0 AS alpine

ARG OS=linux
ARG ARCH=amd64

COPY --from=compress /go/src/github.com/hairyhenderson/go-which/bin/which_${OS}-${ARCH}-slim /bin/which

ARG VCS_REF
ARG VERSION
ARG CODEOWNERS

LABEL org.opencontainers.image.revision=$VCS_REF \
      org.opencontainers.image.title=go-which \
      org.opencontainers.image.authors=$CODEOWNERS \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.source="https://github.com/hairyhenderson/go-which"

ENTRYPOINT [ "/bin/which" ]

FROM scratch AS slim

ARG OS=linux
ARG ARCH=amd64

COPY --from=compress /go/src/github.com/hairyhenderson/go-which/bin/which_${OS}-${ARCH}-slim /bin/which

ARG VCS_REF
ARG VERSION
ARG CODEOWNERS

LABEL org.opencontainers.image.revision=$VCS_REF \
      org.opencontainers.image.title=go-which \
      org.opencontainers.image.authors=$CODEOWNERS \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.source="https://github.com/hairyhenderson/go-which"

ENTRYPOINT [ "/which" ]
