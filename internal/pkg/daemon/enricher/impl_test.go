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

	"github.com/stretchr/testify/require"
)

func TestDefaultImpl_EnvForPid(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		prepare func() *fstest.MapFS
		assert  func(t *testing.T, env map[string]string, retErr error)
	}{
		{
			name: "the best case",
			prepare: func() *fstest.MapFS {
				return &fstest.MapFS{
					"proc/1234/environ": {Data: []byte("hello=world")},
				}
			},
			assert: func(t *testing.T, env map[string]string, retErr error) {
				t.Helper()

				require.NoError(t, retErr)
				require.Equal(t, "world", env["hello"])
			},
		},
		{
			name: "key with empty value",
			prepare: func() *fstest.MapFS {
				return &fstest.MapFS{
					"proc/1234/environ": {Data: []byte("hello=")},
				}
			},
			assert: func(t *testing.T, env map[string]string, retErr error) {
				t.Helper()

				require.NoError(t, retErr)
				require.Len(t, env, 1)
			},
		},
		{
			name: "keys with no equals sign",
			prepare: func() *fstest.MapFS {
				return &fstest.MapFS{
					"proc/1234/environ": {Data: []byte("hello")},
				}
			},
			assert: func(t *testing.T, env map[string]string, retErr error) {
				t.Helper()

				require.NoError(t, retErr)
				require.Empty(t, env)
			},
		},
		{
			name: "empty lines",
			prepare: func() *fstest.MapFS {
				return &fstest.MapFS{
					"proc/1234/environ": {Data: []byte("hello=world\x00\x00\x00test1=test2")},
				}
			},
			assert: func(t *testing.T, env map[string]string, retErr error) {
				t.Helper()

				require.NoError(t, retErr)
				require.Equal(t, "world", env["hello"])
				require.Equal(t, "test2", env["test1"])
				require.Len(t, env, 2)
			},
		},
		{
			name: "incorrect file",
			prepare: func() *fstest.MapFS {
				return &fstest.MapFS{
					"proc/unknown/environ": {Data: []byte("hello=world")},
				}
			},
			assert: func(t *testing.T, env map[string]string, retErr error) {
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
			env, err := testImpl.EnvForPid(1234)
			tc.assert(t, env, err)
		})
	}
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
			name: "arguments with newlines and a long command line",
			prepare: func() *fstest.MapFS {
				long := strings.Repeat("x", 128*1024)

				return &fstest.MapFS{
					"proc/1234/cmdline": {Data: []byte("sh\x00-c\x00echo a\necho b\x00" + long)},
				}
			},
			assert: func(t *testing.T, cmd string, retErr error) {
				t.Helper()

				require.NoError(t, retErr)
				require.Equal(t, "sh -c echo a\necho b "+strings.Repeat("x", 128*1024), cmd)
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
