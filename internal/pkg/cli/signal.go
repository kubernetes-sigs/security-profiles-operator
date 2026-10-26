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

package cli

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// DuplicateSignalWindow is how long another signal after a first one counts
// as the same delivery. A signal sent to the process group of spoc, like the
// SIGINT of a terminal, reaches spoc once directly and once more through a
// parent which forwards it, like the spoc command of the operator.
const DuplicateSignalWindow = time.Second

// IgnoreDuplicateSignals receives the signals of ch for the
// DuplicateSignalWindow after a first signal, and calls stop afterwards, which
// restores the default handling of the signals. It blocks until then.
func IgnoreDuplicateSignals(ch <-chan os.Signal, stop func()) {
	timer := time.NewTimer(DuplicateSignalWindow)
	defer timer.Stop()

	for {
		select {
		case <-ch:
		case <-timer.C:
			stop()

			return
		}
	}
}

// TerminationSignals are the signals which terminate spoc by default. spoc
// handles them itself, so that its commands can clean up, write their results
// or forward them to the command they run. The spoc command of the operator
// forwards the same ones.
var TerminationSignals = []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT}

// SignalContext returns a context which gets canceled on the signals which
// terminate spoc otherwise, so that commands can clean up, for example their
// temporary files. The returned function restores the default handling.
//
// The default handling gets restored shortly after the first signal as well,
// so that a further one terminates spoc, see IgnoreDuplicateSignals. Some
// steps do not stop on the context, like an interactive sign in or a TUF
// refresh, and would otherwise keep spoc running with every further signal
// ignored.
func SignalContext() (context.Context, context.CancelFunc) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, TerminationSignals...)

	ctx, cancel := context.WithCancel(context.Background())

	var once sync.Once

	stopNotify := func() {
		once.Do(func() { signal.Stop(signals) })
	}

	go func() {
		select {
		case <-signals:
			cancel()
			IgnoreDuplicateSignals(signals, stopNotify)
		case <-ctx.Done():
			stopNotify()
		}
	}()

	return ctx, func() {
		cancel()
		stopNotify()
	}
}
