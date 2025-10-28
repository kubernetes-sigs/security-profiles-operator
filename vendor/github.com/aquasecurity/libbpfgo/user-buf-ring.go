package libbpfgo

/*
#cgo LDFLAGS: -lelf -lz
#include "libbpfgo.h"
*/
import "C"
import (
	"fmt"
	"sync"
	"unsafe"
)

//
// UserRingBuffer
//

type UserRingBuffer struct {
	rb      *C.struct_user_ring_buffer
	bpfMap  *BPFMap
	closed  bool
	stop    chan struct{}
	w       chan []byte
	errChan chan error
	wg      sync.WaitGroup
}

func (rb *UserRingBuffer) Start() {
	rb.stop = make(chan struct{})
	rb.errChan = make(chan error, 1)
	rb.wg.Add(1)
	go func() {
		defer rb.wg.Done()
		for {
			select {
			case b := <-rb.w:
				if err := rb.submit(b); err != nil {
					rb.errChan <- err
				}
			case <-rb.stop:
				return
			}
		}
	}()
}

func (rb *UserRingBuffer) Error() error {
	select {
	case err := <-rb.errChan:
		return err
	default:
		return nil
	}
}

func (rb *UserRingBuffer) submit(b []byte) error {
	bSizeC := C.size_t(len(b))
	entry, errno := C.user_ring_buffer__reserve(rb.rb, C.uint(bSizeC))
	if entry == nil {
		return fmt.Errorf("user_ring_buffer__reserve failed: %v", errno)
	}

	C.memcpy(entry, unsafe.Pointer(&b[0]), bSizeC)
	C.user_ring_buffer__submit(rb.rb, entry)
	return nil
}

func (rb *UserRingBuffer) Stop() {
	if rb.stop == nil {
		return
	}
	close(rb.stop)
	rb.wg.Wait()
}

func (rb *UserRingBuffer) Close() {
	if rb.closed {
		return
	}

	rb.Stop()
	C.user_ring_buffer__free(rb.rb)
	rb.closed = true
}
