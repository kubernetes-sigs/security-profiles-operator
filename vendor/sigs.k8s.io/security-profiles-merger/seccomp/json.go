/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package seccomp

import (
	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/internal/strictjson"
	"sigs.k8s.io/security-profiles-merger/spm"
)

// ErrDuplicateKey, ErrUnknownField, ErrInvalidUTF8 and ErrUnexpectedData are
// returned by UnmarshalStrict for a document encoding/json would decode
// without a word: one repeating a member, holding a member no field reads,
// holding a byte the decoder replaces, or followed by more data. See the spm
// package for each.
var (
	ErrDuplicateKey   = spm.ErrDuplicateKey
	ErrUnknownField   = spm.ErrUnknownField
	ErrInvalidUTF8    = spm.ErrInvalidUTF8
	ErrUnexpectedData = spm.ErrUnexpectedData
)

// UnmarshalStrict decodes a seccomp profile and rejects what encoding/json accepts
// silently: members the profile type has no field for, members repeated
// within one object, bytes that are not valid UTF-8, and data behind the
// profile.
//
// Each loses something a reader of an untrusted profile must not lose. A
// misspelled or unknown member drops the rule it was meant to carry. A
// repeated member is read as its last occurrence here and as its first
// elsewhere, so a scanner and the runtime can read one document as two
// profiles. A byte that is not valid UTF-8 is replaced with U+FFFD, so
// names that differ only there decode alike and merge into one rule. Use
// this instead of json.Unmarshal wherever the document comes from somewhere
// else, and validate the result with ValidateArtifact afterwards.
//
// The profile is decoded into as json.Unmarshal decodes into it, so pass a
// zero profile: a member the document omits keeps the value it had.
func UnmarshalStrict(data []byte, profile *specs.LinuxSeccomp) error {
	if profile == nil {
		return ErrNilProfile
	}

	return strictjson.Unmarshal(data, profile)
}
