FROM golang:1.14-alpine AS build
WORKDIR /go/src/saschagrunert/seccomp-operator
RUN apk --no-cache add build-base git gcc

# Speed up build by leveraging docker layer caching
COPY go.mod go.sum ./
RUN go mod download

ADD . /go/src/saschagrunert/seccomp-operator
RUN go build -ldflags '-s -w' -o /seccomp-operator



FROM alpine
LABEL name="Seccomp Operator" \
      version="v0.0.1" \
      description="The Seccomp Operator makes it easier for cluster admins to manage their seccomp profiles and apply them to Kubernetes' workloads."

COPY --from=build /seccomp-operator /
ENTRYPOINT /seccomp-operator