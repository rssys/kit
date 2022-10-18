package comm

import (
	"io"
	"time"
)

type HostComm interface {
	io.ReadWriter
	SetRWDeadline(deadline time.Time) error
}

type GuestComm interface {
	io.ReadWriteCloser
}
