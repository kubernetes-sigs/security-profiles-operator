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

package enricher

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
)

// writes records every write, like a rotating log file which can rotate
// between two of them.
type writes [][]byte

func (w *writes) Write(p []byte) (int, error) {
	*w = append(*w, append([]byte(nil), p...))

	return len(p), nil
}

func TestDefaultImpl_PrintJsonOutput(t *testing.T) {
	t.Parallel()

	var w writes

	newDefaultImpl(logr.Discard()).PrintJsonOutput(&w, []byte(`{"a":1}`))

	require.Equal(t, writes{[]byte("{\"a\":1}\n")}, w, "the record and its newline are one write")
}

func TestDefaultImpl_ExecRequestIDForPID(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("x", 2*maxEnvVarBytes)

	for _, tc := range []struct {
		name    string
		environ string
		want    string
		found   bool
	}{
		{
			name:    "the best case",
			environ: "hello=world\x00" + requestIdEnv + "=request\x00other=value",
			want:    "request",
			found:   true,
		},
		{
			name:    "last variable without NUL",
			environ: "hello=world\x00" + requestIdEnv + "=request",
			want:    "request",
			found:   true,
		},
		{
			name:    "the first of two",
			environ: requestIdEnv + "=first\x00" + requestIdEnv + "=second",
			want:    "first",
			found:   true,
		},
		{name: "empty value", environ: requestIdEnv + "="},
		{name: "no request ID", environ: "hello=world\x00\x00test1=test2"},
		{name: "prefix of another variable", environ: "X" + requestIdEnv + "=request"},
		{name: "empty environment"},
		{
			name:    "after a long variable",
			environ: "LONG=" + long + "\x00" + requestIdEnv + "=request",
			want:    "request",
			found:   true,
		},
		{
			// The rest of a long variable is no variable of its own.
			name:    "inside a long variable",
			environ: "LONG=" + long + requestIdEnv + "=request",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			testImpl := defaultImpl{fsys: fstest.MapFS{
				"proc/1234/environ": {Data: []byte(tc.environ)},
			}}

			got, found, err := testImpl.ExecRequestIDForPID(1234)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
			require.Equal(t, tc.found, found)
		})
	}

	t.Run("missing process", func(t *testing.T) {
		t.Parallel()

		_, _, err := (&defaultImpl{fsys: fstest.MapFS{}}).ExecRequestIDForPID(1234)
		require.ErrorIs(t, err, ErrProcessNotFound)
	})
}

func TestDefaultImpl_CmdlineForPID(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		prepare func() *fstest.MapFS
		assert  func(t *testing.T, cmd string, retErr error)
	}{
		{
			name: "the best case",
			prepare: func() *fstest.MapFS {
				return &fstest.MapFS{
					"proc/1234/cmdline": {Data: []byte("/sh")},
				}
			},
			assert: func(t *testing.T, cmd string, retErr error) {
				t.Helper()

				require.NoError(t, retErr)
				require.Equal(t, "/sh", cmd)
			},
		},
		{
			name: "arguments with newlines",
			prepare: func() *fstest.MapFS {
				return &fstest.MapFS{
					"proc/1234/cmdline": {Data: []byte("sh\x00-c\x00echo a\necho b\x00")},
				}
			},
			assert: func(t *testing.T, cmd string, retErr error) {
				t.Helper()

				require.NoError(t, retErr)
				require.Equal(t, "sh -c echo a\necho b ", cmd)
			},
		},
		{
			name: "a long command line gets cut",
			prepare: func() *fstest.MapFS {
				long := strings.Repeat("x", 128*1024)

				return &fstest.MapFS{
					"proc/1234/cmdline": {Data: []byte("sh\x00" + long)},
				}
			},
			assert: func(t *testing.T, cmd string, retErr error) {
				t.Helper()

				require.NoError(t, retErr)
				require.Equal(t, "sh "+strings.Repeat("x", maxCmdlineBytes-len("sh ")), cmd)
			},
		},
		{
			name: "incorrect file",
			prepare: func() *fstest.MapFS {
				return &fstest.MapFS{
					"proc/unknown/environ": {Data: []byte("/sh")},
				}
			},
			assert: func(t *testing.T, cmd string, retErr error) {
				t.Helper()

				require.Error(t, retErr)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			testImpl := defaultImpl{
				fsys: tc.prepare(),
			}
			cmd, err := testImpl.CmdlineForPID(1234)
			tc.assert(t, cmd, err)
		})
	}
}
