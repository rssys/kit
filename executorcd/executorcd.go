package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sync"
	"time"

	osexec "os/exec"

	"github.com/rss/kit/exec"
	"github.com/rss/kit/pgen"
	"github.com/rss/kit/vm"
	"github.com/rss/kit/vm/comm"
)

var (
	flagVM    = flag.String("vm", "qemu", "vm type")
	flagComm  = flag.String("comm", "virtio", "host-guest communication type")
	flagDebug = flag.Bool("debug", false, "debug")
)

var comms []comm.GuestComm
var dmesg *os.File

func earlyErrf(format string, args ...interface{}) {
	s := fmt.Sprintf("<2>[executord] "+format, args...)
	dmesg.Write([]byte(s))
	dmesg.Sync()
}

func earlyDebugf(format string, args ...interface{}) {
	if *flagDebug {
		earlyErrf(format, args...)
	}
}

func errf(format string, args ...interface{}) {
	s := fmt.Sprintf(format, args...)
	comms[exec.ErrComm].Write([]byte(s))
}

func debugf(format string, args ...interface{}) {
	if *flagDebug {
		errf(format, args...)
	}
}

func compileAndStart(cp *pgen.CProg, waitF, notifyF *os.File, skip, debug bool) (string, error) {
	fPath := "./" + cp.Meta.Name
	binPath := fPath + ".bin"
	err := ioutil.WriteFile(fPath, cp.Code, 0666)
	if err != nil {
		return "", err
	}
	compArgs := []string{}
	compArgs = append(compArgs, cp.Meta.CompFlags...)
	compArgs = append(compArgs, "-o", binPath)
	compArgs = append(compArgs, fPath)
	compCmd := osexec.Command(cp.Meta.Compiler, compArgs...)
	compOut, err := compCmd.CombinedOutput()
	debugf("compiler output: %v", string(compOut))
	if err != nil {
		return "", fmt.Errorf("cannot compile: %v", err)
	}

	// check binary
	// ipvsCmd := osexec.Command("ipvsadm")
	// ipvsOut, err := ipvsCmd.CombinedOutput()
	// debugf("ipvs output: %v", string(ipvsOut))
	// if err != nil {
	// 	return "", fmt.Errorf("cannot run ipvsadm: %v", err)
	// }

	rp, wp, err := os.Pipe()
	if err != nil {
		return "", fmt.Errorf("cannot create pipe: %v", err)
	}
	defer wp.Close()
	runCmd := osexec.Command(binPath)
	runCmd.ExtraFiles = []*os.File{wp, waitF, notifyF}
	if skip {
		debugf("set skip_prog = 1\n")
		runCmd.Env = append(os.Environ(), "SKIP_PROG=1")
	}
	if debug {
		runCmd.Stderr = comms[exec.ErrComm]
	}
	err = runCmd.Start()
	if err != nil {
		return "", fmt.Errorf("cannot run C program: %v", err)
	}
	go func() {
		debugf("I am waiting on program %v...\n", cp.Meta.Name)
		err := runCmd.Wait()
		if err != nil {
			debugf("cannot wait process\n")
		}
		debugf("wait done, program %s exit\n", cp.Meta.Name)
	}()
	buf := make([]byte, 4096)
	rp.SetReadDeadline(time.Now().Add(3 * time.Second))
	l, err := rp.Read(buf)
	if err != nil {
		return "", fmt.Errorf("cannot read trace: %v", err)
	}
	return string(buf[:l]), nil
}

func main() {
	var err error
	var resBuf []byte

	aExecDataBuf := make([]byte, exec.ExecDataBufSize)
	resBuf = make([]byte, exec.ExecResultBufSize)

	comms = make([]comm.GuestComm, exec.CommNum)

	dmesg, err = os.OpenFile("/dev/kmsg", os.O_WRONLY, 0)
	if err != nil {
		os.Exit(-1)
	}
	// printk, err := os.OpenFile("/proc/sys/kernel/printk", os.O_RDWR, 0)
	// if err != nil {
	// 	os.Exit(-1)
	// }
	// printk.Write([]byte("7"))
	// printk.Close()

	ioutil.WriteFile("/proc/sys/net/ipv4/vs/debug_level", []byte("9\000"), 0666)

	earlyDebugf("executorcd is running, args: %v", os.Args)
	earlyDebugf("executorcd is running, args: %v", os.Args)
	earlyDebugf("executorcd is running, args: %v", os.Args)
	earlyDebugf("executorcd is running, args: %v", os.Args)
	earlyDebugf("executorcd is running, args: %v", os.Args)

	flag.Parse()
	// init guest communication
	for i := 0; i < exec.CommNum; i++ {
		c, err := vm.InitGuestComm(*flagVM, *flagComm, i)
		if err != nil {
			earlyErrf("executord cannot open guest comm: %v", err)
			os.Exit(-1)
		}
		comms[i] = c
	}

	err = exec.LoopbackSlave(comms)
	if err != nil {
		earlyErrf("executord cannot open guest comm: %v", err)
		os.Exit(-1)
	}

	log.SetOutput(comms[exec.ErrComm])
	log.Printf("Communication establisted!")
	printkData, err := ioutil.ReadFile("/proc/sys/kernel/printk")
	if err != nil {
		errf("read printk error!")
	}
	log.Printf("Printk arguments: %v", string(printkData))
	aSync1, aSync2, vSync1, vSync2, err := exec.CreateSync()
	if err != nil {
		errf("create sync error: %v\n", err)
		os.Exit(-1)
	}

	err = exec.SendFin(comms)
	if err != nil {
		errf("cannot send finshed signal: %v\n", err)
	}

	// –––––––––––––––––––––– Take snapshot  ––––––––––––––––––––––––
	ctest, err := exec.RecvCTest(comms[exec.InComm], aExecDataBuf)
	if err != nil {
		earlyDebugf("receive test data error: %v\n", err)
		os.Exit(-1)
	}

	debugf("attack prog:\n%v\nvictim prog:\n%v\nskip: %v\n",
		string(ctest.A.Code),
		string(ctest.V.Code),
		ctest.SkipA,
	)

	res := &exec.CTestReport{}
	wg := &sync.WaitGroup{}
	wg.Add(2)
	go func() {
		var err error
		res.ASCTrace, err = compileAndStart(ctest.A, aSync1, aSync2, ctest.SkipA, *flagDebug)
		if err != nil {
			errf("run attack error: %v\n", err)
			os.Exit(-1)
		}
		wg.Done()
	}()
	go func() {
		var err error
		res.VSCTrace, err = compileAndStart(ctest.V, vSync1, vSync2, false, *flagDebug)
		if err != nil {
			errf("run victim error: %v\n", err)
			os.Exit(-1)
		}
		wg.Done()
	}()
	wg.Wait()
	debugf("test done\n")
	// dmesgCmd := osexec.Command("dmesg")
	// dmesgOut, err := dmesgCmd.CombinedOutput()
	// if err != nil {
	// 	errf("cannot run dmesg: %v\n", err)
	// 	os.Exit(-1)
	// }
	// debugf("dmesg: %v", string(dmesgOut))
	err = exec.SendCTestReport(comms[exec.OutComm], res, resBuf)
	if err != nil {
		errf("send test result error: %v\n", err)
		os.Exit(-1)
	}
	debugf("send test result done!\n")
	time.Sleep(10000 * time.Second)
}
