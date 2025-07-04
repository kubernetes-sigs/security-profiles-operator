//go:build linux && !no_bpf && amd64

package auditsource

import _ "embed"

//go:embed bpf/enricher.bpf.o.amd64
var AuditProgram []byte
