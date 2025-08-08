// Copyright 2024 The Tessera authors. All Rights Reserved.
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

package tessera

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"container/list"

	"github.com/transparency-dev/tessera/internal/parse"
	"k8s.io/klog/v2"
)

// NewPublicationAwaiter provides an PublicationAwaiter that can be cancelled
// using the provided context. The PublicationAwaiter will poll every `pollPeriod`
// to fetch checkpoints using the `readCheckpoint` function.
func NewPublicationAwaiter(ctx context.Context, readCheckpoint func(ctx context.Context) ([]byte, error), pollPeriod time.Duration) *PublicationAwaiter {
	a := &PublicationAwaiter{
		waiters: list.New(),
	}
	go a.pollLoop(ctx, readCheckpoint, pollPeriod)
	return a
}

// PublicationAwaiter allows client threads to block until a leaf is published.
// This means it has a sequence number, and been integrated into the tree, and
// a checkpoint has been published for it.
// A single long-lived PublicationAwaiter instance
// should be reused for all requests in the application code as there is some
// overhead to each one; the core of an PublicationAwaiter is a poll loop that
// will fetch checkpoints whenever it has clients waiting.
//
// The expected call pattern is:
//
// i, cp, err := awaiter.Await(ctx, storage.Add(myLeaf))
//
// When used this way, it requires very little code at the point of use to
// block until the new leaf is integrated into the tree.
type PublicationAwaiter struct {
	// This mutex is used to protect all reads and writes to fields below.
	mu sync.Mutex
	// waiters is a linked list of type `waiter` and corresponds to all of the
	// client threads that are currently blocked on this awaiter. The list is
	// not sorted; new clients are simply added to the end. This can be changed
	// if this is the wrong decision, but the reasoning behind this decision is
	// that it is O(1) at the point of adding an entry to simply put it on the
	// end, and O(N) each time we poll to check all clients. Keeping the list
	// sorted by index would reduce the worst case in the poll loop, but increase
	// the cost at the point of adding a new entry.
	//
	// Once a waiter is added to this list, it belongs to the awaiter and the
	// awaiter takes sole responsibility for closing the channel in the waiter.
	waiters *list.List
	// size and checkpoint keep track of the latest seen size and checkpoint as
	// an optimization where the last seen value was already large enough.
	size       uint64
	checkpoint []byte
}

// Await blocks until the IndexFuture is resolved, and this new index has been
// integrated into the log, i.e. the log has made a checkpoint available that
// commits to this new index. When this happens, Await returns the index at
// which the leaf has been added, and a checkpoint that commits to this index.
//
// This operation can be aborted early by cancelling the context. In this event,
// or in the event that there is an error getting a valid checkpoint, an error
// will be returned from this method.
func (a *PublicationAwaiter) Await(ctx context.Context, future IndexFuture) (Index, []byte, error) {
	ctx, span := tracer.Start(ctx, "tessera.Await")
	defer span.End()

	i, err := future()
	if err != nil {
		return i, nil, err
	}
	cp, err := a.await(ctx, i.Index)
	return i, cp, err
}

// pollLoop MUST be called in a goroutine when constructing an PublicationAwaiter
// and will run continually until its context is cancelled. It wakes up every
// `pollPeriod` to check if there are clients blocking. If there are, it requests
// the latest checkpoint from the log, parses the tree size, and releases all clients
// that were blocked on an index smaller than this tree size.
func (a *PublicationAwaiter) pollLoop(ctx context.Context, readCheckpoint func(ctx context.Context) ([]byte, error), pollPeriod time.Duration) {
	for {
		select {
		case <-ctx.Done():
			klog.Info("PublicationAwaiter exiting due to context completion")
			return
		case <-time.After(pollPeriod):
			// It's worth this small lock contention to make sure that no unnecessary
			// work happens in personalities that aren't performing writes.
			a.mu.Lock()
			hasClients := a.waiters.Front() != nil
			a.mu.Unlock()
			if !hasClients {
				continue
			}
		}
		// Note that for now, this releases all clients in the event of a single failure.
		// If this causes problems, this could be changed to attempt retries.
		rawCp, err := readCheckpoint(ctx)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			a.releaseClientsErr(fmt.Errorf("readCheckpoint: %v", err))
			continue
		}
		_, size, _, err := parse.CheckpointUnsafe(rawCp)
		if err != nil {
			a.releaseClientsErr(err)
			continue
		}
		a.releaseClients(size, rawCp)
	}
}

func (a *PublicationAwaiter) await(ctx context.Context, i uint64) ([]byte, error) {
	a.mu.Lock()
	if a.size > i {
		cp := a.checkpoint
		a.mu.Unlock()
		return cp, nil
	}
	done := make(chan checkpointOrDeath, 1)
	w := waiter{
		index:  i,
		result: done,
	}
	a.waiters.PushBack(w)
	a.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case cod := <-done:
		return cod.cp, cod.err
	}
}

func (a *PublicationAwaiter) releaseClientsErr(err error) {
	cod := checkpointOrDeath{
		err: err,
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for e := a.waiters.Front(); e != nil; e = e.Next() {
		w := e.Value.(waiter)
		w.result <- cod
		close(w.result)
	}
	// Clear out the list now we've released everyone
	a.waiters.Init()
}

func (a *PublicationAwaiter) releaseClients(size uint64, cp []byte) {
	cod := checkpointOrDeath{
		cp: cp,
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.size = size
	a.checkpoint = cp
	for e := a.waiters.Front(); e != nil; e = e.Next() {
		w := e.Value.(waiter)
		if w.index < size {
			w.result <- cod
			close(w.result)
			// Need to do this removal after the loop has been fully iterated
			// It still needs to happen inside the mutex, but defers happen in
			// reverse order.
			defer a.waiters.Remove(e)
		}
	}
}

type waiter struct {
	index  uint64
	result chan checkpointOrDeath
}

type checkpointOrDeath struct {
	cp  []byte
	err error
}
