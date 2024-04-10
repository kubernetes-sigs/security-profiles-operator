// Copyright 2023 CUE Labs AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ociclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"unicode"

	"cuelabs.dev/go/oci/ociregistry"
)

// errorBodySizeLimit holds the maximum number of response bytes aallowed in
// the server's error response. A typical error message is around 200
// bytes. Hence, 8 KiB should be sufficient.
const errorBodySizeLimit = 8 * 1024

type wireError struct {
	Code_   string          `json:"code"`
	Message string          `json:"message,omitempty"`
	Detail_ json.RawMessage `json:"detail,omitempty"`
}

func (e *wireError) Error() string {
	var buf strings.Builder
	for _, r := range e.Code_ {
		if r == '_' {
			buf.WriteByte(' ')
		} else {
			buf.WriteRune(unicode.ToLower(r))
		}
	}
	if buf.Len() == 0 {
		buf.WriteString("(no code)")
	}
	if e.Message != "" {
		buf.WriteString(": ")
		buf.WriteString(e.Message)
	}
	if len(e.Detail_) != 0 && !bytes.Equal(e.Detail_, []byte("null")) {
		buf.WriteString("; detail: ")
		buf.Write(e.Detail_)
	}
	return buf.String()
}

// Code implements [ociregistry.Error.Code].
func (e *wireError) Code() string {
	return e.Code_
}

// Detail implements [ociregistry.Error.Detail].
func (e *wireError) Detail() any {
	if len(e.Detail_) == 0 {
		return nil
	}
	// TODO do this once only?
	var d any
	json.Unmarshal(e.Detail_, &d)
	return d
}

// Is makes it possible for users to write `if errors.Is(err, ociregistry.ErrBlobUnknown)`
// even when the error hasn't exactly wrapped that error.
func (e *wireError) Is(err error) bool {
	var rerr ociregistry.Error
	return errors.As(err, &rerr) && rerr.Code() == e.Code()
}

type wireErrors struct {
	httpStatusCode int
	Errors         []wireError `json:"errors"`
}

func (e *wireErrors) Unwrap() []error {
	// TODO we could do this only once.
	errs := make([]error, len(e.Errors))
	for i := range e.Errors {
		errs[i] = &e.Errors[i]
	}
	return errs
}

// Is makes it possible for users to write `if errors.Is(err, ociregistry.ErrRangeInvalid)`
// even when the error hasn't exactly wrapped that error.
func (e *wireErrors) Is(err error) bool {
	switch e.httpStatusCode {
	case http.StatusRequestedRangeNotSatisfiable:
		return err == ociregistry.ErrRangeInvalid
	}
	return false
}

func (e *wireErrors) Error() string {
	var buf strings.Builder
	buf.WriteString(strconv.Itoa(e.httpStatusCode))
	buf.WriteString(" ")
	buf.WriteString(http.StatusText(e.httpStatusCode))
	buf.WriteString(": ")
	buf.WriteString(e.Errors[0].Error())
	for i := range e.Errors[1:] {
		buf.WriteString("; ")
		buf.WriteString(e.Errors[i+1].Error())
	}
	return buf.String()
}

// makeError forms an error from a non-OK response.
func makeError(resp *http.Response) error {
	if resp.Request.Method == "HEAD" {
		// When we've made a HEAD request, we can't see any of
		// the actual error, so we'll have to make up something
		// from the HTTP status.
		var err error
		switch resp.StatusCode {
		case http.StatusNotFound:
			err = ociregistry.ErrNameUnknown
		case http.StatusUnauthorized:
			err = ociregistry.ErrUnauthorized
		case http.StatusForbidden:
			err = ociregistry.ErrDenied
		case http.StatusTooManyRequests:
			err = ociregistry.ErrTooManyRequests
		case http.StatusBadRequest:
			err = ociregistry.ErrUnsupported
		default:
			return fmt.Errorf("error response: %v", resp.Status)
		}
		return fmt.Errorf("error response: %v: %w", resp.Status, err)
	}
	if !isJSONMediaType(resp.Header.Get("Content-Type")) || resp.Request.Method == "HEAD" {
		// TODO include some of the body in this case?
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("error response: %v; body: %q", resp.Status, data)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, errorBodySizeLimit+1))
	if err != nil {
		return fmt.Errorf("%s: cannot read error body: %v", resp.Status, err)
	}
	if len(data) > errorBodySizeLimit {
		// TODO include some part of the body
		return fmt.Errorf("error body too large")
	}
	var errs wireErrors
	if err := json.Unmarshal(data, &errs); err != nil {
		return fmt.Errorf("%s: malformed error response: %v", resp.Status, err)
	}
	if len(errs.Errors) == 0 {
		return fmt.Errorf("%s: no errors in body (probably a server issue)", resp.Status)
	}
	errs.httpStatusCode = resp.StatusCode
	return &errs
}

// isJSONMediaType reports whether the content type implies
// that the content is JSON.
func isJSONMediaType(contentType string) bool {
	mediaType, _, _ := mime.ParseMediaType(contentType)
	m := strings.TrimPrefix(mediaType, "application/")
	if len(m) == len(mediaType) {
		return false
	}
	// Look for +json suffix. See https://tools.ietf.org/html/rfc6838#section-4.2.8
	// We recognize multiple suffixes too (e.g. application/something+json+other)
	// as that seems to be a possibility.
	for {
		i := strings.Index(m, "+")
		if i == -1 {
			return m == "json"
		}
		if m[0:i] == "json" {
			return true
		}
		m = m[i+1:]
	}
}
