package exec

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"
	"time"

	"github.com/google/syzkaller/prog"
	"github.com/rss/kit/vm"
	"github.com/rss/kit/vm/comm"
)

// TODO: need to clean the code in this file

func loopbackMaster(inst *vm.Instance, timeout time.Duration) error {
	var err error

	sendbuf := make([]byte, 4)
	recvbuf := make([]byte, 4)
	for i := 0; i < CommNum; i++ {
		err = inst.Comm(i).SetRWDeadline(time.Now().Add(timeout))
		if err != nil {
			return fmt.Errorf("cannot set r/w deadline: %v", err)
		}
	}
	defer func() {
		// reset deadline
		for i := 0; i < CommNum; i++ {
			err = inst.Comm(i).SetRWDeadline(time.Time{})
		}
	}()
	for i := 0; i < CommNum; i++ {
		binary.LittleEndian.PutUint32(sendbuf, uint32(i*123+456))
		_, err = inst.Comm(i).Write(sendbuf)
		if err != nil {
			return fmt.Errorf("cannot write to comm %v: %v", i, err)
		}
		_, err := io.ReadFull(inst.Comm((i+1)%CommNum), recvbuf)
		if err != nil {
			return fmt.Errorf("cannot read from comm %v: %v", (i+1)%CommNum, err)
		}
		if !bytes.Equal(sendbuf, recvbuf) {
			return fmt.Errorf("return bytes %v, expect %v", recvbuf, sendbuf)
		}
	}
	return nil
}

func LoopbackSlave(comms []comm.GuestComm) error {
	recvbuf := make([]byte, 4)
	for i := 0; i < CommNum; i++ {
		_, err := io.ReadFull(comms[i], recvbuf)
		if err != nil {
			return fmt.Errorf("cannot read from comm %v: %v", i, err)
		}
		_, err = comms[(i+1)%CommNum].Write(recvbuf)
		if err != nil {
			return fmt.Errorf("cannot write to comm %v: %v", (i+1)%CommNum, err)
		}
	}
	return nil
}

func recvFin(inst *vm.Instance) (err error) {
	var l int
	buf := make([]byte, 4)
	// increase to 20s to let container finish setup
	err = inst.Comm(OutComm).SetRWDeadline(time.Now().Add(20 * time.Second))
	// reset deadline
	defer inst.Comm(OutComm).SetRWDeadline(time.Time{})
	if err != nil {
		return
	}
	l, err = inst.Comm(OutComm).Read(buf)
	if err != nil {
		return
	}
	if string(buf[:l]) != "fin" {
		return fmt.Errorf("expect fin, get %v", string(buf))
	}
	return nil
}

func SendFin(comms []comm.GuestComm) error {
	_, err := comms[OutComm].Write([]byte("fin"))
	if err != nil {
		return err
	}
	return nil
}

func SendCTest(inst *vm.Instance, c *CTest, buf []byte) (err error) {
	w := bytes.NewBuffer(nil)
	enc := gob.NewEncoder(w)
	err = enc.Encode(c)
	if err != nil {
		return err
	}
	data := w.Bytes()
	l := uint32(len(data))
	binary.LittleEndian.PutUint32(buf[:4], l)
	copy(buf[4:], w.Bytes())
	_, err = inst.Comm(InComm).Write(buf[:l+4])
	if err != nil {
		return
	}
	return
}

func RecvCTest(c comm.GuestComm, buf []byte) (cp *CTest, err error) {
	var tmpBuf [4]byte

	_, err = io.ReadFull(c, tmpBuf[:4])
	if err != nil {
		return nil, err
	}
	l := int(binary.LittleEndian.Uint32(tmpBuf[:4]))
	if l > len(buf) {
		buf = make([]byte, l)
	}
	_, err = io.ReadFull(c, buf[:l])
	if err != nil {
		return nil, fmt.Errorf("cannot read C prog data: %v", err)
	}
	r := bytes.NewBuffer(buf[:l])
	dec := gob.NewDecoder(r)
	cp = &CTest{}
	err = dec.Decode(cp)
	if err != nil {
		return nil, fmt.Errorf("cannot parse C prog data: %v", err)
	}
	return cp, nil
}

// func SendCTest(inst *vm.Instance, ct *CTest, buf []byte) (err error) {
// 	err = sendCProg(inst, ct.A, buf)
// 	if err != nil {
// 		return err
// 	}
// 	err = sendCProg(inst, ct.V, buf)
// 	if err != nil {
// 		return err
// 	}
// 	inst.Comm(InComm).Write()
// 	return nil
// }

// func RecvCTest(c comm.GuestComm, buf []byte) (ct *CTest, err error) {
// 	ct = &CTest{}
// 	ct.A, err = recvCProg(c, buf)
// 	if err != nil {
// 		return nil, err
// 	}
// 	ct.V, err = recvCProg(c, buf)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return ct, nil
// }

func SendCTestReport(c comm.GuestComm, r *CTestReport, buf []byte) error {
	w := bytes.NewBuffer(nil)
	enc := gob.NewEncoder(w)
	err := enc.Encode(r)
	if err != nil {
		return err
	}
	data := w.Bytes()
	l := len(data)
	if l+4 > len(buf) {
		buf = make([]byte, l+4)
	}
	binary.LittleEndian.PutUint32(buf[:4], uint32(l))
	copy(buf[4:], data)

	_, err = c.Write(buf[:l+4])
	if err != nil {
		return err
	}
	return nil
}

func RecvCTestReport(inst *vm.Instance, buf []byte) (*CTestReport, error) {
	var tmpBuf [4]byte

	_, err := io.ReadFull(inst.Comm(OutComm), tmpBuf[:4])
	if err != nil {
		return nil, err
	}
	l := int(binary.LittleEndian.Uint32(tmpBuf[:4]))
	if l > len(buf) {
		buf = make([]byte, l)
	}
	_, err = io.ReadFull(inst.Comm(OutComm), buf[:l])
	if err != nil {
		return nil, err
	}
	r := bytes.NewBuffer(buf[:l])
	dec := gob.NewDecoder(r)
	cr := &CTestReport{}
	err = dec.Decode(cr)
	if err != nil {
		return nil, fmt.Errorf("cannot decode C test report: %v", err)
	}
	return cr, nil
}

func sendExecData(inst *vm.Instance, e *ExecData, buf []byte) (err error) {
	var progLen, totalLen int
	var bufStart []byte

	progBuf := e.P.Serialize()
	progLen = len(progBuf)
	totalLen = 4 + 8 + progLen
	if totalLen > len(buf) {
		buf = make([]byte, totalLen)
	}
	bufStart = buf
	binary.LittleEndian.PutUint32(bufStart[:4], uint32(totalLen))
	bufStart = bufStart[4:]
	binary.LittleEndian.PutUint64(bufStart[:8], uint64(e.Opts.Flags))
	bufStart = bufStart[8:]
	copy(bufStart, progBuf)
	_, err = inst.Comm(InComm).Write(buf[:totalLen])
	if err != nil {
		return
	}
	return
}

func recvExecData(c comm.GuestComm, progTarget *prog.Target, buf []byte) (e *ExecData, err error) {
	var tmpBuf [4]byte
	var bufStart []byte
	var totalLen int

	_, err = io.ReadFull(c, tmpBuf[:4])
	if err != nil {
		return nil, err
	}
	totalLen = int(binary.LittleEndian.Uint32(tmpBuf[:4]))
	if totalLen > len(buf) {
		buf = make([]byte, totalLen)
	}
	bufStart = buf[:]
	totalLen -= 4 // already read 4 bytes
	_, err = io.ReadFull(c, bufStart[:totalLen])
	if err != nil {
		return nil, fmt.Errorf("cannot read exec data: %v", err)
	}
	e = &ExecData{}
	e.Opts.Flags = ExecFlags(binary.LittleEndian.Uint64(bufStart[:8]))
	bufStart = bufStart[8:]
	e.P, err = progTarget.Deserialize(bufStart[:totalLen-8], prog.NonStrict)
	if err != nil {
		return nil, err
	}
	return
}

func sendTest(inst *vm.Instance, test *Test, buf []byte) (err error) {
	err = sendExecData(inst, test.A, buf)
	if err != nil {
		return fmt.Errorf("send attack exec: %v", err)
	}
	err = sendExecData(inst, test.V, buf)
	if err != nil {
		return fmt.Errorf("send victim exec: %v", err)
	}
	return
}

func RecvTest(c comm.GuestComm, progTarget *prog.Target, aBuf []byte, vBuf []byte) (t *Test, err error) {
	t = &Test{}
	t.A, err = recvExecData(c, progTarget, aBuf)
	if err != nil {
		return nil, fmt.Errorf("recv attack exec: %v", err)
	}
	t.V, err = recvExecData(c, progTarget, vBuf)
	if err != nil {
		return nil, fmt.Errorf("recv victim exec: %v", err)
	}
	return
}

func sendExecResult(c comm.GuestComm, execRes *ExecResult, buf []byte) (err error) {
	var stderrLen, stdoutLen int
	var bufStart []byte

	stderrLen = len(execRes.Stderr)
	stdoutLen = len(execRes.Stdout)
	totalLen := 4*4 + stderrLen + stdoutLen
	if totalLen > len(buf) {
		buf = make([]byte, totalLen)
	}
	bufStart = buf

	binary.LittleEndian.PutUint32(bufStart[:4], uint32(totalLen))
	bufStart = bufStart[4:]
	if execRes.Hanged {
		binary.LittleEndian.PutUint32(bufStart[:4], uint32(1))
	} else {
		binary.LittleEndian.PutUint32(bufStart[:4], uint32(0))
	}
	bufStart = bufStart[4:]
	binary.LittleEndian.PutUint32(bufStart[:4], uint32(stderrLen))
	bufStart = bufStart[4:]
	binary.LittleEndian.PutUint32(bufStart[:4], uint32(stdoutLen))
	bufStart = bufStart[4:]
	copy(bufStart, execRes.Stderr)
	bufStart = bufStart[stderrLen:]
	copy(bufStart, execRes.Stdout)
	_, err = c.Write(buf[:totalLen])
	if err != nil {
		return
	}
	return
}

func recvExecResult(inst *vm.Instance, buf []byte) (execRes *ExecResult, err error) {
	var tmpBuf [4]byte
	var bufStart []byte
	var stderrLen, stdoutLen, hanged uint32
	var totalLen int
	// var l int

	_, err = io.ReadFull(inst.Comm(OutComm), tmpBuf[:4])
	if err != nil {
		return nil, err
	}
	totalLen = int(binary.LittleEndian.Uint32(tmpBuf[:4]))
	totalLen -= 4 // already read 4 bytes
	if totalLen > len(buf) {
		buf = make([]byte, totalLen)
	}
	bufStart = buf[:totalLen]
	_, err = io.ReadFull(inst.Comm(OutComm), bufStart)
	if err != nil {
		return nil, err
	}
	hanged = binary.LittleEndian.Uint32(bufStart[:4])
	bufStart = bufStart[4:]
	stderrLen = binary.LittleEndian.Uint32(bufStart[:4])
	bufStart = bufStart[4:]
	stdoutLen = binary.LittleEndian.Uint32(bufStart[:4])
	bufStart = bufStart[4:]
	execRes = &ExecResult{}
	execRes.Stderr = bufStart[:stderrLen]
	bufStart = bufStart[stderrLen:]
	execRes.Stdout = bufStart[:stdoutLen]
	if hanged == 1 {
		execRes.Hanged = true
	} else if hanged == 0 {
		execRes.Hanged = false
	} else {
		err = fmt.Errorf("hanged bytes should be 0/1, get %v", hanged)
	}
	return
}

func SendTestResult(c []comm.GuestComm, testRes *TestResult, buf []byte) (err error) {
	err = sendExecResult(c[OutComm], testRes.A, buf)
	if err != nil {
		return fmt.Errorf("send attack test result: %v", err)
	}
	err = sendExecResult(c[OutComm], testRes.V, buf)
	if err != nil {
		return fmt.Errorf("send victim test result: %v", err)
	}
	return nil

}

func recvTestResult(inst *vm.Instance, aBuf []byte, vBuf []byte) (t *TestResult, err error) {
	t = &TestResult{}
	t.A, err = recvExecResult(inst, aBuf)
	if err != nil {
		return nil, err
	}
	t.V, err = recvExecResult(inst, vBuf)
	if err != nil {
		return nil, err
	}
	return
}
