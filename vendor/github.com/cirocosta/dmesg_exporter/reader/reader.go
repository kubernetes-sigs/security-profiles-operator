package reader

import (
	"context"
	"io"
	"syscall"

	"github.com/cirocosta/dmesg_exporter/kmsg"
	"github.com/pkg/errors"
)

type Reader interface {
	Listen(ctx context.Context, messages chan<- *kmsg.Message) (errors chan error)
}

type kmsgReader struct {
	file io.Reader
}

func NewReader(r io.Reader) (reader Reader) {
	reader = &kmsgReader{
		file: r,
	}

	return
}

const readBufferSize = 4096

func (r *kmsgReader) Listen(ctx context.Context, messages chan<- *kmsg.Message) (errChan chan error) {
	errChan = make(chan error, 1)

	go func() {
		defer close(errChan)

		err := r.consumeDevice(ctx, messages)
		if err != nil {
			errChan <- err
			return
		}

		return
	}()

	return
}

func (r *kmsgReader) consumeDevice(ctx context.Context, messages chan<- *kmsg.Message) (err error) {
	var (
		buffer  = make([]byte, readBufferSize)
		n       int
		message *kmsg.Message
		done    = make(chan error, 1)
	)

	defer close(messages)

	go func() {
		var err error

		defer func() {
			done <- err
		}()

		for {
			n, err = r.file.Read(buffer)
			if err != nil {
				if err == io.EOF {
					err = nil
					return
				}

				if err == syscall.EPIPE {
					err = nil
					return
				}

				err = errors.Wrapf(err,
					"unexpected failure while reading file")
				return
			}

			message, err = kmsg.Parse(string(buffer[:n]))
			if err != nil {
				err = errors.Wrapf(err,
					"failed to parse raw message")
				return
			}

			messages <- message
		}
	}()

	select {
	case err = <-done:
	case <-ctx.Done():
		err = ctx.Err()
	}

	return
}
