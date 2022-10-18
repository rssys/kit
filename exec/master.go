package exec

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"

	"github.com/rss/kit/pgen"
	"github.com/rss/kit/vm"
)

type ExecData struct {
	Opts ExecOpts
	P    *prog.Prog
}

type ExecResult struct {
	Stdout []byte
	Stderr []byte
	Hanged bool
}

type ExecReport struct {
	Info   *ProgInfo
	Stderr []byte
	Hanged bool
}

type Test struct {
	A *ExecData
	V *ExecData
}

type TestResult struct {
	A *ExecResult
	V *ExecResult
}

type TestReport struct {
	A *ExecReport
	V *ExecReport
}

type CTest struct {
	A     *pgen.CProg
	V     *pgen.CProg
	SkipA bool
}

type CTestReport struct {
	ASCTrace string
	VSCTrace string
}

type stderrHandler struct {
	inst      *vm.Instance
	buf       []byte
	done      chan bool
	waitClose bool
}

type ExecutorMaster struct {
	Index int

	inst        *vm.Instance
	AExecResBuf []byte
	VExecResBuf []byte
	ExecDataBuf []byte
	cProg       bool

	errHandler *stderrHandler

	// TODO: use RPC to communicate with executor?
	// TCP has states, will it work normally after VM reset?
}

const (
	InComm = iota
	OutComm
	ErrComm

	CommNum
)

const (
	ExecDataBufSize   = 64 << 10
	ExecResultBufSize = 2 * outputSize
)

func executordCmdArgs(vmType, commType, executor string, signal, extraSignal bool, slowdown int, debug bool) string {
	return fmt.Sprintf("-vm=%v -comm=%v -executor=%v -signal=%v -extra_signal=%v -slowdown=%v  -debug=%v", vmType, commType, executor, signal, extraSignal, slowdown, debug)
}

func initStderrHandler(inst *vm.Instance, debug bool) (h *stderrHandler) {
	h = &stderrHandler{
		inst: inst,
	}
	h.buf = make([]byte, 16<<10)
	h.done = make(chan bool)
	go func() {
		reader := bufio.NewReader(h.inst.Comm(ErrComm))
		for {
			s, err := reader.ReadString('\n')
			if err != nil {
				log.Logf(0, "stderr reader is closed: %v", err)
				if h.waitClose {
					log.Logf(0, "probably someone is closing stderr handler")
				}
				break
			} else if debug {
				log.Logf(0, "[executord] %v", s)
			}
		}
		close(h.done)
	}()
	return
}

func (h *stderrHandler) Close() {
	h.waitClose = true
	err := h.inst.Comm(ErrComm).SetRWDeadline(time.Now())
	if err == nil {
		<-h.done
	}
}

func CreateSnapshot(inst *vm.Instance, vmType, commType, executord, executor string, signal, extraSignal bool, slowdown int, debug bool) error {
	var err error
	var executordGuest, executorGuest string
	var cmdArgs string

	executordGuest, err = inst.Copy(executord)
	if err != nil {
		return fmt.Errorf("cannot copy binary %v: %v", executord, err)
	}
	executorGuest, err = inst.Copy(executor)
	if err != nil {
		return fmt.Errorf("cannot copy binary %v: %v", executor, err)
	}
	cmdArgs = executordCmdArgs(vmType, commType, executorGuest, signal, extraSignal, slowdown, debug)
	// run executord as daemon
	_, _, _, _, err = inst.RawRun(fmt.Sprintf("nohup %v %v > foo.out 2> foo.err < /dev/null &", executordGuest, cmdArgs))
	if err != nil {
		return fmt.Errorf("cannot run executord: %v", err)
	}
	err = loopbackMaster(inst, 40*time.Second)
	if err != nil {
		return fmt.Errorf("loopback test fail: %v", err)
	}
	h := initStderrHandler(inst, debug)
	defer h.Close()
	// handle err comm
	err = recvFin(inst)
	if err != nil {
		return fmt.Errorf("recv fail: %v\ne", err)
	}
	// sleep to let some namespace init kernel threads finish?
	time.Sleep(time.Second * 20)
	inst.SaveSnapshot()
	log.Logf(0, "create snapshot finished")
	return nil
}

// TODO: maybe merge this one with the above one
func CreateCProgSnapshot(inst *vm.Instance, vmType, commType, executorcd, header string, debug bool) error {
	var cmdArgs string

	executorcdGuest, err := inst.Copy(executorcd)
	if err != nil {
		return fmt.Errorf("cannot copy binary %v: %v", executorcd, err)
	}
	_, err = inst.Copy(header)
	if err != nil {
		return fmt.Errorf("cannot copy header %v: %v", header, err)
	}
	cmdArgs = fmt.Sprintf("-vm=%v -comm=%v -debug=%v", vmType, commType, debug)
	// run executord as daemon
	_, _, _, _, err = inst.RawRun(fmt.Sprintf("nohup %v %v > foo.out 2> foo.err < /dev/null &", executorcdGuest, cmdArgs))
	if err != nil {
		return fmt.Errorf("cannot run executorcd: %v", err)
	}
	err = loopbackMaster(inst, 20*time.Second)
	if err != nil {
		return fmt.Errorf("loopback test fail: %v", err)
	}
	h := initStderrHandler(inst, debug)
	defer h.Close()
	// handle err comm
	err = recvFin(inst)
	if err != nil {
		return fmt.Errorf("recv fail: %v\ne", err)
	}
	// sleep to let some namespace init kernel threads finish?
	time.Sleep(time.Second * 10)
	inst.SaveSnapshot()
	log.Logf(0, "create snapshot for executing C programs finished")
	return nil
}

func InitExecutorMaster(index int, inst *vm.Instance, cProg, debug bool) *ExecutorMaster {
	e := &ExecutorMaster{
		Index:       index,
		inst:        inst,
		ExecDataBuf: make([]byte, ExecDataBufSize),
		AExecResBuf: make([]byte, ExecResultBufSize),
		VExecResBuf: make([]byte, ExecResultBufSize),
		cProg:       cProg,
	}
	e.inst.LoadSnapshot()
	e.errHandler = initStderrHandler(inst, debug)
	return e
}

func (nsexec *ExecutorMaster) clearIOBuffer(index int, buf []byte) {
	deadline := time.Now().Add(1000 * time.Millisecond)
	nsexec.inst.Comm(index).SetRWDeadline(deadline)
	io.ReadFull(nsexec.inst.Comm(index), buf)
	// reset deadline
	nsexec.inst.Comm(index).SetRWDeadline(time.Time{})
}

func genExecReport(res *ExecResult, p *prog.Prog) (rep *ExecReport, err error) {
	rep = &ExecReport{}
	rep.Info, err = parseOutput(res.Stdout, p)
	if err != nil {
		return nil, err
	}
	rep.Hanged = res.Hanged
	rep.Stderr = make([]byte, len(res.Stderr))
	copy(rep.Stderr, res.Stderr)
	return
}

func GenReport(res *TestResult, ap, vp *prog.Prog) (rep *TestReport, err error) {
	rep = &TestReport{}
	rep.A, err = genExecReport(res.A, ap)
	if err != nil {
		return nil, fmt.Errorf("cannot generate attack program exec report: %v", err)
	}
	rep.V, err = genExecReport(res.V, vp)
	if err != nil {
		return nil, fmt.Errorf("cannot generate victim program exec report: %v", err)
	}
	return rep, nil
}

func (nsexec *ExecutorMaster) Run(test *Test, maxTime time.Duration) (rep *TestReport, timeOut bool, err error) {
	var res *TestResult
	rep = &TestReport{}

	if nsexec.cProg {
		err = fmt.Errorf("cannot call this function when executor is for C programs")
		return nil, false, err
	}

	deadline := time.Now().Add(maxTime)
	err = nsexec.inst.Comm(InComm).SetRWDeadline(deadline)
	if err != nil {
		err = fmt.Errorf("cannot set r/w deadline for in comm: %v", err)
		goto out
	}
	err = nsexec.inst.Comm(OutComm).SetRWDeadline(deadline)
	if err != nil {
		err = fmt.Errorf("cannot set r/w deadline out comm: %v", err)
		goto out
	}
	err = sendTest(nsexec.inst, test, nsexec.ExecDataBuf)
	if err != nil {
		if os.IsTimeout(err) {
			goto timeout
		}
		err = fmt.Errorf("send test data error: %v", err)
		goto out
	}
	res, err = recvTestResult(nsexec.inst, nsexec.AExecResBuf, nsexec.VExecResBuf)
	if err != nil {
		if os.IsTimeout(err) {
			goto timeout
		}
		err = fmt.Errorf("recv test data error: %v", err)
		goto out
	}

	rep, err = GenReport(res, test.A.P, test.V.P)
	if err != nil {
		err = fmt.Errorf("cannot generate test report: %v", err)
		goto out
	}
out:
	// reset deadline
	nsexec.inst.Comm(InComm).SetRWDeadline(time.Time{})
	nsexec.inst.Comm(OutComm).SetRWDeadline(time.Time{})
	nsexec.inst.Comm(ErrComm).SetRWDeadline(time.Time{})
	nsexec.inst.LoadSnapshot()
	return rep, false, err
timeout:
	// clean garbage in fifo buffer
	nsexec.clearIOBuffer(InComm, nsexec.AExecResBuf)
	nsexec.inst.LoadSnapshot()
	nsexec.clearIOBuffer(OutComm, nsexec.AExecResBuf)
	return rep, true, nil
}

func (nsexec *ExecutorMaster) Close() {
	nsexec.errHandler.Close()
	nsexec.inst.Close()
}

func (nsexec *ExecutorMaster) RunCTest(test *CTest, maxTime time.Duration) (rep *CTestReport, timeOut bool, err error) {
	rep = &CTestReport{}

	if !nsexec.cProg {
		err = fmt.Errorf("cannot call this function when executor is NOT for C programs")
		return nil, false, err
	}

	deadline := time.Now().Add(maxTime)
	err = nsexec.inst.Comm(InComm).SetRWDeadline(deadline)
	if err != nil {
		err = fmt.Errorf("cannot set r/w deadline for in comm: %v", err)
		goto out
	}
	err = nsexec.inst.Comm(OutComm).SetRWDeadline(deadline)
	if err != nil {
		err = fmt.Errorf("cannot set r/w deadline out comm: %v", err)
		goto out
	}
	err = SendCTest(nsexec.inst, test, nsexec.ExecDataBuf)
	if err != nil {
		if os.IsTimeout(err) {
			goto timeout
		}
		err = fmt.Errorf("send C test error: %v", err)
		goto out
	}
	rep, err = RecvCTestReport(nsexec.inst, nsexec.AExecResBuf)
	if err != nil {
		if os.IsTimeout(err) {
			goto timeout
		}
		err = fmt.Errorf("recv test data error: %v", err)
		goto out
	}

out:
	// reset deadline
	nsexec.inst.Comm(InComm).SetRWDeadline(time.Time{})
	nsexec.inst.Comm(OutComm).SetRWDeadline(time.Time{})
	nsexec.inst.Comm(ErrComm).SetRWDeadline(time.Time{})
	nsexec.inst.LoadSnapshot()
	return rep, false, err
timeout:
	// clean garbage in fifo buffer
	nsexec.clearIOBuffer(InComm, nsexec.AExecResBuf)
	nsexec.inst.LoadSnapshot()
	nsexec.clearIOBuffer(OutComm, nsexec.AExecResBuf)
	return rep, true, nil
}
