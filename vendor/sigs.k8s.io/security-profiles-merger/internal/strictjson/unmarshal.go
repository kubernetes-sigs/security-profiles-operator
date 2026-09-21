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

package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"sigs.k8s.io/security-profiles-merger/spm"
)

// Unmarshal decodes one JSON document into target and refuses what
// encoding/json accepts silently: a byte that is not valid UTF-8
// (spm.ErrInvalidUTF8), a member repeated within one object
// (spm.ErrDuplicateKey), a member the target type has no field for
// (spm.ErrUnknownField), and anything but whitespace behind the document
// (spm.ErrUnexpectedData).
//
// It reports the first kind of problem it finds, naming every member of that
// kind up to a bound, rather than collecting all kinds: a document that
// fails one check is not one whose other findings can be trusted. target is
// only written once every check has passed, so a caller that goes on after
// an error does not hold what the document said.
func Unmarshal[T any](data []byte, target *T) error {
	err := InvalidUTF8(data)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(bytes.NewReader(data))

	var decoded T

	err = decoder.Decode(&decoded)
	if err != nil {
		return fmt.Errorf("decode profile: %w", err)
	}

	// Decode stops at the end of the first value, so anything behind it
	// would otherwise be ignored.
	_, err = decoder.Token()
	if !errors.Is(err, io.EOF) {
		return spm.ErrUnexpectedData
	}

	paths, omitted := DuplicateKeys(data)

	err = PathsError(spm.ErrDuplicateKey, paths, omitted)
	if err != nil {
		return err
	}

	paths, omitted = UnknownFieldsOf[T](data)

	err = PathsError(spm.ErrUnknownField, paths, omitted)
	if err != nil {
		return err
	}

	*target = decoded

	return nil
}
