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

// Package tailer follows a log file which is appended to, rotated and
// truncated, like the audit log.
package tailer

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

const (
	// DefaultPollInterval is how often a file is checked for new lines, a
	// rotation or a truncation when no interval is configured and the file
	// system does not notify about them.
	DefaultPollInterval = 100 * time.Millisecond

	// watchedPollInterval is the shortest poll interval while the file system
	// notifies about the changes, when polling only catches up on what the
	// notifications missed.
	watchedPollInterval = time.Second

	// watchRetryInterval is how often watching the directory of the file is
	// tried again while it fails, like while the directory does not exist yet
	// or no more notification instances are available.
	watchRetryInterval = 10 * time.Second

	// maxLineSize bounds the bytes kept of a line which is still being
	// written. A longer line is dropped, it is not a log line.
	maxLineSize = 1024 * 1024

	// readSize is the chunk size of the reads.
	readSize = 64 * 1024
)

// errStopped ends the reading when the tailer got stopped.
var errStopped = errors.New("tailer stopped")

// Config configures a Tailer.
type Config struct {
	// PollInterval is how often the file is checked for new lines, a
	// rotation or a truncation once its end is reached, if the file system
	// does not notify about them. While it does, the file is checked on each
	// notification, and polled at least a second apart only to catch up on
	// missed ones. Zero means DefaultPollInterval.
	PollInterval time.Duration
	// FromStart reads the file from its beginning instead of from its
	// current end.
	FromStart bool
}

// Tailer follows a file and sends its complete lines, without their line
// break, to Lines. A file which does not exist yet is read from its start once
// it appears. A file which got replaced (renamed and created again) is read
// from the start of the new file, and a file which got truncated from its new
// beginning.
//
// The lines are read as soon as the file system notifies about them, since
// the readers of the audit log look up the processes of the lines, which may
// exit right after they got logged. The file is polled if the notifications
// are not available.
type Tailer struct {
	path   string
	config Config
	lines  chan string
	// done is closed by Stop, stopped once the reading goroutine returned.
	done     chan struct{}
	stopped  chan struct{}
	stopOnce sync.Once

	mu  sync.Mutex
	err error

	// The fields below belong to the reading goroutine.
	// watcher is nil while the file system notifications are not available,
	// watching is tried again from nextWatch on then.
	watcher   *fsnotify.Watcher
	nextWatch time.Time
	file      *os.File
	info      os.FileInfo
	offset    int64
	// pending is the line which is still being written.
	pending []byte
	// discarding is set while the rest of a line which is too long, or
	// which was partially written when the tailer started, is skipped.
	discarding bool
	buf        []byte
}

// Follow starts following the file at path. A file which does not exist is
// waited for, every other error opening it is returned.
func Follow(path string, config Config) (*Tailer, error) {
	if config.PollInterval <= 0 {
		config.PollInterval = DefaultPollInterval
	}

	t := &Tailer{
		path:    path,
		config:  config,
		lines:   make(chan string),
		done:    make(chan struct{}),
		stopped: make(chan struct{}),
		buf:     make([]byte, readSize),
	}

	if err := t.open(!config.FromStart); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	t.watch()

	go t.run()

	return t, nil
}

// Lines returns the channel of the complete lines. It is closed once the
// tailer stopped, or once it failed: Err tells which.
func (t *Tailer) Lines() <-chan string {
	return t.lines
}

// Err returns the error which ended the tailer, if any.
func (t *Tailer) Err() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.err
}

// Stop stops following the file and releases it. It returns once the reading
// goroutine ended and Lines got closed.
func (t *Tailer) Stop() {
	t.stopOnce.Do(func() {
		close(t.done)
	})

	<-t.stopped
}

// watch starts watching the directory of the file, which tells about the
// writes to the file as well as about its replacement. If that fails, polling
// takes over until it is tried again at nextWatch.
func (t *Tailer) watch() {
	t.nextWatch = time.Now().Add(watchRetryInterval)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return
	}

	if err := watcher.Add(filepath.Dir(t.path)); err != nil {
		watcher.Close()

		return
	}

	t.watcher = watcher
}

func (t *Tailer) closeWatcher() {
	if t.watcher != nil {
		t.watcher.Close()
		t.watcher = nil
	}
}

// pollInterval returns the interval of the polling, which only catches up on
// missed notifications while there are notifications.
func (t *Tailer) pollInterval() time.Duration {
	if t.watcher != nil {
		return max(t.config.PollInterval, watchedPollInterval)
	}

	return t.config.PollInterval
}

func (t *Tailer) run() {
	defer close(t.stopped)
	defer close(t.lines)
	defer t.closeFile()
	defer t.closeWatcher()

	ticker := time.NewTicker(t.pollInterval())
	defer ticker.Stop()

	for {
		if err := t.poll(); err != nil {
			if !errors.Is(err, errStopped) {
				t.mu.Lock()
				t.err = err
				t.mu.Unlock()
			}

			return
		}

		if !t.wait(ticker) {
			return
		}
	}
}

// wait returns once the file may have changed, or false once the tailer got
// stopped.
func (t *Tailer) wait(ticker *time.Ticker) bool {
	// A nil channel never receives, which leaves the polling.
	var (
		events <-chan fsnotify.Event
		errs   <-chan error
	)

	if t.watcher != nil {
		events, errs = t.watcher.Events, t.watcher.Errors
	}

	for {
		select {
		case <-t.done:
			return false

		case <-ticker.C:
			if t.watcher == nil && time.Now().After(t.nextWatch) {
				t.watch()

				if t.watcher != nil {
					ticker.Reset(t.pollInterval())
				}
			}

			return true

		case event, ok := <-events:
			if !ok {
				t.dropWatcher(ticker)

				return true
			}

			// Writes to the other files of the directory do not matter.
			if filepath.Clean(event.Name) == filepath.Clean(t.path) {
				t.drainEvents()

				return true
			}

		case _, ok := <-errs:
			if !ok {
				t.dropWatcher(ticker)
			}

			// An overflow of the notifications is caught up by polling.
			return true
		}
	}
}

// drainEvents drops the notifications which are queued already, since the
// poll which follows reads everything they tell about. A busy file would
// otherwise get polled once per write.
func (t *Tailer) drainEvents() {
	for {
		select {
		case _, ok := <-t.watcher.Events:
			if !ok {
				return
			}
		default:
			return
		}
	}
}

// dropWatcher falls back to polling once the watcher stopped.
func (t *Tailer) dropWatcher(ticker *time.Ticker) {
	t.closeWatcher()
	t.nextWatch = time.Now().Add(watchRetryInterval)
	ticker.Reset(t.pollInterval())
}

// poll sends the lines appended since the last poll and picks up a file which
// appeared, got replaced or got truncated.
func (t *Tailer) poll() error {
	if t.file == nil {
		if err := t.open(false); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}

			return err
		}
	}

	if err := t.read(); err != nil {
		return err
	}

	return t.checkFile()
}

// open opens the file, at its end if seekEnd is set.
func (t *Tailer) open(seekEnd bool) error {
	file, err := os.Open(filepath.Clean(t.path))
	if err != nil {
		return err
	}

	info, err := file.Stat()
	if err != nil {
		file.Close()

		return err
	}

	var offset int64

	if seekEnd {
		offset, err = file.Seek(0, io.SeekEnd)
		if err != nil {
			file.Close()

			return err
		}
	}

	t.file, t.info, t.offset = file, info, offset
	t.pending = t.pending[:0]
	// The end of the file may be in the middle of a line which is still being
	// written, its rest would be sent as a line of its own.
	t.discarding = seekEnd && offset > 0 && !endsWithNewline(file, offset)

	return nil
}

// endsWithNewline reports whether the byte before offset is a line break.
func endsWithNewline(file *os.File, offset int64) bool {
	var last [1]byte

	n, err := file.ReadAt(last[:], offset-1)

	return n == 1 && err == nil && last[0] == '\n'
}

func (t *Tailer) closeFile() {
	if t.file != nil {
		t.file.Close()
		t.file = nil
	}
}

// read sends the complete lines which can be read from the file.
func (t *Tailer) read() error {
	for {
		n, err := t.file.Read(t.buf)
		if n > 0 {
			t.offset += int64(n)

			if err := t.consume(t.buf[:n]); err != nil {
				return err
			}
		}

		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}

			return err
		}
	}
}

// consume sends the complete lines of data, keeping the rest for the next
// read.
func (t *Tailer) consume(data []byte) error {
	for len(data) > 0 {
		end := bytes.IndexByte(data, '\n')
		if end < 0 {
			t.keep(data)

			return nil
		}

		if t.discarding {
			t.discarding = false
		} else {
			line := data[:end]
			if len(t.pending) > 0 {
				line = append(t.pending, line...)
			}

			if err := t.send(string(bytes.TrimSuffix(line, []byte{'\r'}))); err != nil {
				return err
			}
		}

		t.pending = t.pending[:0]
		data = data[end+1:]
	}

	return nil
}

// keep holds on to the start of a line, unless it is too long to be one.
func (t *Tailer) keep(data []byte) {
	if t.discarding {
		return
	}

	if len(t.pending)+len(data) > maxLineSize {
		t.pending = t.pending[:0]
		t.discarding = true

		return
	}

	t.pending = append(t.pending, data...)
}

func (t *Tailer) send(line string) error {
	select {
	case t.lines <- line:
		return nil
	case <-t.done:
		return errStopped
	}
}

// checkFile switches to the file which replaced the followed one, and starts
// over on a file which got truncated. A file which is gone is kept, its
// writer may not have reopened it yet. The new lines are read right away,
// since no further notification may come for them.
func (t *Tailer) checkFile() error {
	info, err := os.Stat(t.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}

		return err
	}

	if !os.SameFile(info, t.info) {
		// Whatever got written to the old file since the last read comes
		// before the lines of the new one.
		if err := t.read(); err != nil {
			return err
		}

		t.closeFile()

		if err := t.open(false); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}

			return err
		}

		return t.read()
	}

	if info.Size() < t.offset {
		if _, err := t.file.Seek(0, io.SeekStart); err != nil {
			return err
		}

		t.offset = 0
		t.pending = t.pending[:0]
		t.discarding = false

		return t.read()
	}

	return nil
}
