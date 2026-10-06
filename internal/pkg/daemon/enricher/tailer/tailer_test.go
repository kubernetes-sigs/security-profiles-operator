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

package tailer

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/stretchr/testify/require"
)

const (
	testPollInterval = 10 * time.Millisecond
	testTimeout      = time.Minute
)

func testConfig() Config {
	return Config{PollInterval: testPollInterval}
}

// nextLine returns the next line, or fails the test if none arrives in time.
func nextLine(t *testing.T, sut *Tailer) string {
	t.Helper()

	select {
	case line, ok := <-sut.Lines():
		require.True(t, ok, "lines closed: %v", sut.Err())

		return line
	case <-time.After(testTimeout):
		t.Fatal("no line received")

		return ""
	}
}

// noLine asserts that no line arrives within a few poll intervals.
func noLine(t *testing.T, sut *Tailer) {
	t.Helper()

	select {
	case line := <-sut.Lines():
		t.Fatalf("unexpected line %q", line)
	case <-time.After(10 * testPollInterval):
	}
}

// waitClosed asserts that Lines gets closed.
func waitClosed(t *testing.T, sut *Tailer) {
	t.Helper()

	for {
		select {
		case _, ok := <-sut.Lines():
			if !ok {
				return
			}
		case <-time.After(testTimeout):
			t.Fatal("lines not closed")
		}
	}
}

func write(t *testing.T, file *os.File, content string) {
	t.Helper()

	_, err := file.WriteString(content)
	require.NoError(t, err)
}

func startFollow(t *testing.T, config Config) (*Tailer, *os.File) {
	t.Helper()

	return startTailer(t, config, func(*Tailer) {})
}

// startTailer follows a new file, after prepare changed the tailer.
func startTailer(t *testing.T, config Config, prepare func(*Tailer)) (*Tailer, *os.File) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "audit.log")

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	require.NoError(t, err)

	t.Cleanup(func() { file.Close() })

	sut := newTailer(path, config)
	prepare(sut)
	require.NoError(t, sut.start())

	t.Cleanup(sut.Stop)

	return sut, file
}

// receive returns the next value of ch, or fails the test if none arrives in
// time.
func receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()

	select {
	case value := <-ch:
		return value
	case <-time.After(testTimeout):
		t.Fatal("nothing received")

		var zero T

		return zero
	}
}

func TestFollowSendsCompleteLines(t *testing.T) {
	t.Parallel()

	sut, file := startFollow(t, testConfig())

	// A line which is still being written is held back.
	write(t, file, "first")
	noLine(t, sut)

	write(t, file, " line\r\nsecond\nthird")
	require.Equal(t, "first line", nextLine(t, sut))
	require.Equal(t, "second", nextLine(t, sut))
	noLine(t, sut)

	write(t, file, "\n")
	require.Equal(t, "third", nextLine(t, sut))
}

func TestFollowReadsOnNotifications(t *testing.T) {
	t.Parallel()

	// The polling never kicks in, so the lines are only read when the file
	// system notifies about them.
	sut, file := startFollow(t, Config{PollInterval: time.Hour})

	write(t, file, "first\n")
	require.Equal(t, "first", nextLine(t, sut))

	// The writes to the other files of the directory are no lines.
	other := filepath.Join(filepath.Dir(file.Name()), "other.log")
	require.NoError(t, os.WriteFile(other, []byte("other\n"), 0o600))
	noLine(t, sut)

	write(t, file, "second\n")
	require.Equal(t, "second", nextLine(t, sut))

	// A replaced file is followed as well.
	require.NoError(t, os.Rename(file.Name(), file.Name()+".1"))
	require.NoError(t, os.WriteFile(file.Name(), []byte("third\n"), 0o600))
	require.Equal(t, "third", nextLine(t, sut))
}

func TestFollowStartsAtEnd(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "audit.log")
	require.NoError(t, os.WriteFile(path, []byte("old\npartial"), 0o600))

	sut, err := Follow(path, testConfig())
	require.NoError(t, err)

	t.Cleanup(sut.Stop)

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	require.NoError(t, err)

	t.Cleanup(func() { file.Close() })

	// The rest of the line being written when the tailer started is not a
	// line of its own.
	write(t, file, " line\nnew\n")
	require.Equal(t, "new", nextLine(t, sut))
}

func TestFollowFromStart(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "audit.log")
	require.NoError(t, os.WriteFile(path, []byte("old\n"), 0o600))

	sut, err := Follow(path, Config{PollInterval: testPollInterval, FromStart: true})
	require.NoError(t, err)

	t.Cleanup(sut.Stop)

	require.Equal(t, "old", nextLine(t, sut))
}

func TestFollowWaitsForFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "audit.log")

	sut, err := Follow(path, testConfig())
	require.NoError(t, err)

	t.Cleanup(sut.Stop)

	noLine(t, sut)

	// A file which appears later is read from its start.
	require.NoError(t, os.WriteFile(path, []byte("created\n"), 0o600))
	require.Equal(t, "created", nextLine(t, sut))
}

func TestFollowReopensRotatedFile(t *testing.T) {
	t.Parallel()

	sut, file := startFollow(t, testConfig())
	path := file.Name()

	write(t, file, "before\n")
	require.Equal(t, "before", nextLine(t, sut))

	// The file gets renamed away, the writer keeps writing to it until it
	// reopens the path.
	require.NoError(t, os.Rename(path, path+".1"))
	write(t, file, "after rename\n")
	require.Equal(t, "after rename", nextLine(t, sut))

	// The new file is read from its start.
	newFile, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	require.NoError(t, err)

	t.Cleanup(func() { newFile.Close() })

	write(t, newFile, "new file\n")
	require.Equal(t, "new file", nextLine(t, sut))

	// The old file is not followed any more.
	write(t, file, "old file\n")
	noLine(t, sut)
}

func TestFollowRotatedFileKeepsOrder(t *testing.T) {
	t.Parallel()

	sut, file := startFollow(t, testConfig())
	path := file.Name()

	// The file gets rotated before the tailer polls again: what was
	// written to the old file comes first.
	require.NoError(t, os.Rename(path, path+".1"))
	write(t, file, "old\n")
	require.NoError(t, os.WriteFile(path, []byte("new\n"), 0o600))

	require.Equal(t, "old", nextLine(t, sut))
	require.Equal(t, "new", nextLine(t, sut))
}

func TestFollowStartsOverOnTruncation(t *testing.T) {
	t.Parallel()

	sut, file := startFollow(t, testConfig())

	write(t, file, "first line\npartial")
	require.Equal(t, "first line", nextLine(t, sut))

	// The partial line gets read in the meantime, so that the truncation is
	// noticed by the size, not by the content.
	noLine(t, sut)

	require.NoError(t, file.Truncate(0))

	_, err := file.Seek(0, 0)
	require.NoError(t, err)

	write(t, file, "new\n")
	require.Equal(t, "new", nextLine(t, sut))
}

func TestFollowDropsOverlongLine(t *testing.T) {
	t.Parallel()

	sut, file := startFollow(t, testConfig())

	write(t, file, strings.Repeat("x", maxLineSize+1))
	noLine(t, sut)

	write(t, file, "rest\nnext\n")
	require.Equal(t, "next", nextLine(t, sut))
}

func TestStopClosesLines(t *testing.T) {
	t.Parallel()

	sending := make(chan struct{}, 1)

	sut, file := startTailer(t, testConfig(), func(sut *Tailer) {
		sut.sending = func() { sending <- struct{}{} }
	})

	// Nobody reads the line, the tailer is blocked sending it.
	write(t, file, "unread\n")
	receive(t, sending)

	stopped := make(chan struct{})

	go func() {
		defer close(stopped)

		sut.Stop()
		sut.Stop()
	}()

	select {
	case <-stopped:
	case <-time.After(testTimeout):
		t.Fatal("stop did not return")
	}

	waitClosed(t, sut)
	require.NoError(t, sut.Err())
}

func TestFollowUnreadableFile(t *testing.T) {
	t.Parallel()

	// A directory can be opened, but not read.
	sut, err := Follow(t.TempDir(), Config{PollInterval: testPollInterval, FromStart: true})
	require.NoError(t, err)

	t.Cleanup(sut.Stop)

	waitClosed(t, sut)
	require.Error(t, sut.Err())
}

func TestFollowOpenError(t *testing.T) {
	t.Parallel()

	if os.Geteuid() == 0 {
		t.Skip("root can read every file")
	}

	path := filepath.Join(t.TempDir(), "audit.log")
	require.NoError(t, os.WriteFile(path, nil, 0o000))

	_, err := Follow(path, testConfig())
	require.Error(t, err)
}

var errTest = errors.New("test")

// TestFollowPollsWithoutNotifications asserts that the file is polled when the
// file system notifications are not available.
func TestFollowPollsWithoutNotifications(t *testing.T) {
	t.Parallel()

	sut, file := startTailer(t, testConfig(), func(sut *Tailer) {
		sut.newWatcher = func() (*fsnotify.Watcher, error) { return nil, errTest }
	})

	write(t, file, "first\n")
	require.Equal(t, "first", nextLine(t, sut))

	// A replaced file is followed as well.
	require.NoError(t, os.Rename(file.Name(), file.Name()+".1"))
	require.NoError(t, os.WriteFile(file.Name(), []byte("second\n"), 0o600))
	require.Equal(t, "second", nextLine(t, sut))
}

// TestFollowWatchesAgain asserts that the tailer polls once its watcher
// stopped, and watches the file again after the retry interval.
func TestFollowWatchesAgain(t *testing.T) {
	t.Parallel()

	watchers := make(chan *fsnotify.Watcher, 2)

	sut, file := startTailer(t, testConfig(), func(sut *Tailer) {
		sut.watchRetry = testPollInterval
		sut.newWatcher = func() (*fsnotify.Watcher, error) {
			watcher, err := fsnotify.NewWatcher()
			if err == nil {
				select {
				case watchers <- watcher:
				default:
				}
			}

			return watcher, err
		}
	})

	first := receive(t, watchers)

	// The watcher stops, like when the notifications overflow its queue.
	require.NoError(t, first.Close())

	write(t, file, "polled\n")
	require.Equal(t, "polled", nextLine(t, sut))

	second := receive(t, watchers)
	require.NotSame(t, first, second)

	write(t, file, "watched\n")
	require.Equal(t, "watched", nextLine(t, sut))
}
