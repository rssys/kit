package qemu

import (
	"errors"
	"fmt"
	"os"
	"path"
	"sync"
	"syscall"
	"time"
)

type VirtioSerialHost struct {
	Index        int
	hostFifoIn   *os.File // host commmunication handler
	hostFifoOut  *os.File // host commmunication handler
	hostFifoPath string
}

type VirtioSerialGuest struct {
	Index        int
	guestFile    *os.File
	guestDevPath string
	lock         sync.Mutex
}

func virtioSerialName(index int) string {
	return fmt.Sprintf("virtio-serial-%v", index)
}

func InitVirtioGuest(index int) (*VirtioSerialGuest, error) {
	var v *VirtioSerialGuest
	var err error

	v = &VirtioSerialGuest{
		Index: index,
		// We don't know the exact mapping between virtio-serial index and /dev/vportNp1,
		// as observed that N might start from 0 in some cases.
		// With a special udev rule:
		// KERNEL=="vport*", ATTR{name}=="?*",	SYMLINK+="virtio-ports/$attr{name}
		// /dev/virtio-ports/{name} will be a symlink to actual /dev/vportNp1.
		// So we can establish the mapping between virtio-serial name and /dev/vportNp1.
		guestDevPath: fmt.Sprintf("/dev/virtio-ports/%v", virtioSerialName(index)),
	}
	v.guestFile, err = os.OpenFile(v.guestDevPath, os.O_RDWR, 0000)
	if err != nil {
		return nil, fmt.Errorf("cannot open virtio device %v: %v", v.guestDevPath, err)
	}
	return v, nil
}

const MaxChunkSize = 8 << 10

var ErrHostNotConnected = errors.New("host not connected")

func (v *VirtioSerialGuest) Read(data []byte) (int, error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	return v.guestFile.Read(data)
}

func (v *VirtioSerialGuest) Write(data []byte) (int, error) {
	v.lock.Lock()
	defer v.lock.Unlock()
	return v.guestFile.Write(data)
}

func (v *VirtioSerialGuest) Close() error {
	return v.guestFile.Close()
}

// qemu args to create virtio serial device
func (v *VirtioSerialHost) VMArg() []string {
	return []string{
		"-chardev",
		fmt.Sprintf("pipe,id=chardev-%v,path=%v", v.Index, v.hostFifoPath),
		"-device",
		"virtio-serial",
		"-device",
		fmt.Sprintf("virtserialport,chardev=chardev-%v,name=%v", v.Index, virtioSerialName(v.Index)),
	}
}

// Init virtio host fifo. Serial port is always set to 1.
func initVirtioHost(index int, workdir string) (*VirtioSerialHost, error) {

	var fifo, fifo_in, fifo_out string
	var err error
	var v *VirtioSerialHost

	// create fifo in workdir
	fifo = path.Join(workdir, fmt.Sprintf("virtio_pipe_%v", index))
	fifo_in = fifo + ".in"
	fifo_out = fifo + ".out"
	err = syscall.Mkfifo(fifo_in, 0666)
	if err != nil {
		return nil, err
	}
	err = syscall.Mkfifo(fifo_out, 0666)
	if err != nil {
		return nil, err
	}
	v = &VirtioSerialHost{
		Index:        index,
		hostFifoPath: fifo,
	}
	v.hostFifoIn, err = os.OpenFile(fifo_in, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	v.hostFifoOut, err = os.OpenFile(fifo_out, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	return v, nil
}

func (v *VirtioSerialHost) SetRWDeadline(deadline time.Time) error {
	err := v.hostFifoIn.SetDeadline(deadline)
	if err != nil {
		return err
	}
	err = v.hostFifoOut.SetDeadline(deadline)
	return err
}

func (v *VirtioSerialHost) Read(data []byte) (int, error) {
	return v.hostFifoOut.Read(data)
}

func (v *VirtioSerialHost) Write(data []byte) (int, error) {
	return v.hostFifoIn.Write(data)
}

func (v *VirtioSerialHost) Close() error {
	err := v.hostFifoIn.Close()
	if err != nil {
		return err
	}
	err = v.hostFifoOut.Close()
	return err

}
