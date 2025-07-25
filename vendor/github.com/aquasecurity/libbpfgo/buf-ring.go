package libbpfgo

/*
#cgo LDFLAGS: -lelf -lz
#include "libbpfgo.h"
*/
import "C"

import (
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"
)

//
// RingBuffer
//

type RingBuffer struct {
	rb       *C.struct_ring_buffer
	bpfMap   *BPFMap
	slots    []uint
	closed   bool
	wg       sync.WaitGroup
	stopFlag uint32 // use with atomic operations
}

// Poll will wait until timeout in milliseconds to gather
// data from the ring buffer.
func (rb *RingBuffer) Poll(timeout int) {
	rb.wg.Add(1)
	go rb.poll(timeout)
}

// Deprecated: use RingBuffer.Poll() instead.
func (rb *RingBuffer) Start() {
	rb.Poll(300)
}

func (rb *RingBuffer) Stop() {
	if atomic.LoadUint32(&rb.stopFlag) == 1 {
		return
	}

	// Signal the poll goroutine to exit
	atomic.StoreUint32(&rb.stopFlag, 1)

	// The event channel should be drained here since the consumer
	// may have stopped at this point. Failure to drain it will
	// result in a deadlock: the channel will fill up and the poll
	// goroutine will block in the callback.
	for _, slot := range rb.slots {
		eventChan := eventChannels.get(slot).(chan []byte)
		go func() {
			// revive:disable:empty-block
			for range eventChan {
			}
			// revive:enable:empty-block
		}()
	}

	// Wait for the poll goroutine to exit
	rb.wg.Wait()

	// Close the channel -- this is useful for the consumer but
	// also to terminate the drain goroutine above.
	for _, slot := range rb.slots {
		eventChan := eventChannels.get(slot).(chan []byte)
		close(eventChan)
	}
}

func (rb *RingBuffer) Close() {
	if rb.closed {
		return
	}

	rb.Stop()
	C.ring_buffer__free(rb.rb)
	for _, slot := range rb.slots {
		eventChannels.remove(slot)
	}
	rb.closed = true
}

func (rb *RingBuffer) poll(timeout int) error {
	defer rb.wg.Done()

	stopFlag := (*C.uint32_t)(unsafe.Pointer(&rb.stopFlag))
	ret := C.cgo_ring_buffer__poll(rb.rb, C.int(timeout), stopFlag)
	if ret < 0 {
		return fmt.Errorf("error polling perf buffer: %w", syscall.Errno(-ret))
	}

	return nil
}
