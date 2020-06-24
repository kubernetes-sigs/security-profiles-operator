FROM golang:1.14-alpine AS build
WORKDIR /go/src/saschagrunert/seccomp-operator
RUN apk --no-cache add build-base git gcc

ENV USER=secuser
ENV UID=2000
# See https://stackoverflow.com/a/55757473/12429735RUN 
RUN adduser \    
    --disabled-password \    
    --gecos "" \    
    --home "/nonexistent" \    
    --shell "/sbin/nologin" \    
    --no-create-home \    
    --uid "${UID}" \    
    "${USER}"

# Speed up build by leveraging docker layer caching
COPY go.mod go.sum ./
RUN go mod download

ADD . /go/src/saschagrunert/seccomp-operator
RUN make

FROM alpine
LABEL name="Seccomp Operator" \
      version="v0.0.1" \
      description="The Seccomp Operator makes it easier for cluster admins to manage their seccomp profiles and apply them to Kubernetes' workloads."

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /etc/passwd /etc/passwd
COPY --from=build /etc/group /etc/group
COPY --from=build /build/seccomp-operator /

ENTRYPOINT /seccomp-operator
