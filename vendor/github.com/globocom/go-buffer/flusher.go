package buffer

type (
	// Flusher represents a destination of buffered data.
	Flusher interface {
		Write(items []interface{})
	}

	// FlusherFunc represents a flush function.
	FlusherFunc func(items []interface{})
)

func (fn FlusherFunc) Write(items []interface{}) {
	fn(items)
}
