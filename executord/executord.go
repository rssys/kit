package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"runtime"
	"sync"
	"time"

	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/rss/kit/exec"
	"github.com/rss/kit/vm"
	"github.com/rss/kit/vm/comm"
)

var (
	flagVM          = flag.String("vm", "qemu", "vm type")
	flagComm        = flag.String("comm", "virtio", "host-guest communication type")
	flagExecutor    = flag.String("executor", "", "executor path")
	flagSignal      = flag.Bool("signal", true, "coverage feedback")
	flagExtraSignal = flag.Bool("extra_signal", true, "extra coverage feedback")
	flagSlowdown    = flag.Int("slowdown", 1, "basic slowdown; exec module will increase slowdown for memory trace")
	flagDebug       = flag.Bool("debug", true, "debug")
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

func main() {
	var err error
	var envConfig *exec.Config
	var sysTarget *targets.Target
	var progTarget *prog.Target
	var aEnv, vEnv *exec.Env
	var aExecDataBuf, vExecDataBuf []byte
	var resBuf []byte
	var test *exec.Test
	var res *exec.TestResult

	aExecDataBuf = make([]byte, exec.ExecDataBufSize)
	vExecDataBuf = make([]byte, exec.ExecDataBufSize)
	resBuf = make([]byte, exec.ExecResultBufSize)

	comms = make([]comm.GuestComm, exec.CommNum)

	dmesg, err = os.OpenFile("/dev/kmsg", os.O_WRONLY, 0)
	if err != nil {
		os.Exit(-1)
	}
	printk, err := os.OpenFile("/proc/sys/kernel/printk", os.O_WRONLY, 0)
	if err != nil {
		os.Exit(-1)
	}
	printk.Write([]byte("7"))
	printk.Close()

	earlyDebugf("executord is running, args: %v", os.Args)

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

	// close in main thread
	// comms[exec.ErrComm].Close()
	// errChan = make(chan string)
	// go func() {
	// 	// open in log thread
	// 	c, err := vm.InitGuestComm(*flagVM, *flagComm, exec.ErrComm)
	// 	if err != nil {
	// 		earlyErrf("executord cannot open guest comm: %v", err)
	// 		os.Exit(-1)
	// 	}
	// 	for {
	// 		s := <-errChan
	// 		c.Write([]byte(s))
	// 	}
	// }()

	log.SetOutput(comms[exec.ErrComm])
	log.Printf("Communication establisted!")
	progTarget, err = prog.GetTarget(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		errf("get prog target error: %v\n", err)
		os.Exit(-1)
	}

	err = exec.SetupUser()
	if err != nil {
		errf("setup user error: %v\n", err)
		os.Exit(-1)
	}

	sysTarget = targets.Get(runtime.GOOS, runtime.GOARCH)
	envConfig = &exec.Config{
		Executor:      *flagExecutor,
		UseShmem:      true,
		UseForkServer: true,
		Flags:         exec.FlagSandboxNamespace | exec.FlagEnableTun | exec.FlagEnableNetDev | exec.FlagEnableCgroups,
		Timeouts:      sysTarget.Timeouts(*flagSlowdown),
	}
	if *flagSignal {
		envConfig.Flags |= exec.FlagSignal
	}
	if *flagExtraSignal {
		envConfig.Flags |= exec.FlagExtraCover
	}
	if *flagDebug {
		envConfig.Flags |= exec.FlagDebug
	}
	aEnv, err = exec.MakeEnv(envConfig, exec.AttackerPid)
	if err != nil {
		errf("make attack env error: %v\n", err)
		os.Exit(-1)
	}
	vEnv, err = exec.MakeEnv(envConfig, exec.VictimPid)
	if err != nil {
		errf("make victim env error: %v\n", err)
		os.Exit(-1)
	}
	aSync1, aSync2, vSync1, vSync2, err := exec.CreateSync()
	if err != nil {
		errf("create sync error: %v\n", err)
		os.Exit(-1)
	}
	tmpDirPath := "./shared"
	err = os.Mkdir(tmpDirPath, 0777)
	if err != nil {
		errf("cannot create shared directory: %v\n", err)
		os.Exit(-1)
	}
	os.Mkdir(path.Join(tmpDirPath, "syz-tmp"), 0777)
	err = aEnv.StartEnv(tmpDirPath, comms[exec.ErrComm], aSync1, aSync2)
	if err != nil {
		errf("start attack env error: %v\n", err)
		os.Exit(-1)
	}
	err = vEnv.StartEnv(tmpDirPath, comms[exec.ErrComm], vSync1, vSync2)
	if err != nil {
		errf("start victim env error: %v\n", err)
		os.Exit(-1)
	}
	err = exec.SendFin(comms)
	if err != nil {
		errf("cannot send finshed signal: %v\n", err)
	}
	// –––––––––––––––––––––– Take snapshot  ––––––––––––––––––––––––

	test, err = exec.RecvTest(comms[exec.InComm], progTarget, aExecDataBuf, vExecDataBuf)
	if err != nil {
		earlyDebugf("receive test data error: %v\n", err)
		os.Exit(-1)
	}

	debugf("attack flag:\n%v\nattack prog:\n%v\nvictim flag:\n%v\nvictim prog:\n%v\n",
		test.A.Opts.Flags,
		test.A.P.String(),
		test.V.Opts.Flags,
		test.V.P.String(),
	)
	res = &exec.TestResult{
		A: &exec.ExecResult{},
		V: &exec.ExecResult{},
	}
	var err1, err2 error
	wg := &sync.WaitGroup{}
	wg.Add(2)
	go func() {
		res.A.Stdout, res.A.Stderr, res.A.Hanged, err1 = aEnv.Exec(&test.A.Opts, test.A.P)
		wg.Done()
	}()
	go func() {
		res.V.Stdout, res.V.Stderr, res.V.Hanged, err2 = vEnv.Exec(&test.V.Opts, test.V.P)
		wg.Done()
	}()
	wg.Wait()
	if err1 != nil {
		errf("run attack error: %v\n", err)
		os.Exit(-1)
	}
	if err2 != nil {
		errf("run victim error: %v\n", err)
		os.Exit(-1)
	}
	debugf("sending test result:\nattack\nstdout size: %v\nstderr size: %v\nhanged: %v\nvictim\nstdout size: %v\nstderr size: %v\nhanged: %v\n",
		len(res.A.Stdout), len(res.A.Stderr), res.A.Hanged, len(res.V.Stdout), len(res.V.Stderr), res.V.Hanged)
	err = exec.SendTestResult(comms, res, resBuf)
	if err != nil {
		errf("send test result error: %v\n", err)
		os.Exit(-1)
	}
	debugf("send test result done!\n")
	time.Sleep(10000 * time.Second)
	// if err != nil {
	// 	return
	// }
	// defaultMountFlags := unix.MS_NOEXEC | unix.MS_NOSUID | unix.MS_NODEV
	// var devices []*devices.Rule
	// for _, device := range specconv.AllowedDevices {
	// 	devices = append(devices, &device.Rule)
	// }
	// config := &configs.Config{
	// 	Rootfs: "/your/path/to/rootfs",
	// 	Capabilities: &configs.Capabilities{
	// 		Bounding: []string{
	// 			"CAP_CHOWN",
	// 			"CAP_DAC_OVERRIDE",
	// 			"CAP_FSETID",
	// 			"CAP_FOWNER",
	// 			"CAP_MKNOD",
	// 			"CAP_NET_RAW",
	// 			"CAP_SETGID",
	// 			"CAP_SETUID",
	// 			"CAP_SETFCAP",
	// 			"CAP_SETPCAP",
	// 			"CAP_NET_BIND_SERVICE",
	// 			"CAP_SYS_CHROOT",
	// 			"CAP_KILL",
	// 			"CAP_AUDIT_WRITE",
	// 		},
	// 		Effective: []string{
	// 			"CAP_CHOWN",
	// 			"CAP_DAC_OVERRIDE",
	// 			"CAP_FSETID",
	// 			"CAP_FOWNER",
	// 			"CAP_MKNOD",
	// 			"CAP_NET_RAW",
	// 			"CAP_SETGID",
	// 			"CAP_SETUID",
	// 			"CAP_SETFCAP",
	// 			"CAP_SETPCAP",
	// 			"CAP_NET_BIND_SERVICE",
	// 			"CAP_SYS_CHROOT",
	// 			"CAP_KILL",
	// 			"CAP_AUDIT_WRITE",
	// 		},
	// 		Inheritable: []string{
	// 			"CAP_CHOWN",
	// 			"CAP_DAC_OVERRIDE",
	// 			"CAP_FSETID",
	// 			"CAP_FOWNER",
	// 			"CAP_MKNOD",
	// 			"CAP_NET_RAW",
	// 			"CAP_SETGID",
	// 			"CAP_SETUID",
	// 			"CAP_SETFCAP",
	// 			"CAP_SETPCAP",
	// 			"CAP_NET_BIND_SERVICE",
	// 			"CAP_SYS_CHROOT",
	// 			"CAP_KILL",
	// 			"CAP_AUDIT_WRITE",
	// 		},
	// 		Permitted: []string{
	// 			"CAP_CHOWN",
	// 			"CAP_DAC_OVERRIDE",
	// 			"CAP_FSETID",
	// 			"CAP_FOWNER",
	// 			"CAP_MKNOD",
	// 			"CAP_NET_RAW",
	// 			"CAP_SETGID",
	// 			"CAP_SETUID",
	// 			"CAP_SETFCAP",
	// 			"CAP_SETPCAP",
	// 			"CAP_NET_BIND_SERVICE",
	// 			"CAP_SYS_CHROOT",
	// 			"CAP_KILL",
	// 			"CAP_AUDIT_WRITE",
	// 		},
	// 		Ambient: []string{
	// 			"CAP_CHOWN",
	// 			"CAP_DAC_OVERRIDE",
	// 			"CAP_FSETID",
	// 			"CAP_FOWNER",
	// 			"CAP_MKNOD",
	// 			"CAP_NET_RAW",
	// 			"CAP_SETGID",
	// 			"CAP_SETUID",
	// 			"CAP_SETFCAP",
	// 			"CAP_SETPCAP",
	// 			"CAP_NET_BIND_SERVICE",
	// 			"CAP_SYS_CHROOT",
	// 			"CAP_KILL",
	// 			"CAP_AUDIT_WRITE",
	// 		},
	// 	},
	// 	Namespaces: configs.Namespaces([]configs.Namespace{
	// 		{Type: configs.NEWNS},
	// 		{Type: configs.NEWUTS},
	// 		{Type: configs.NEWIPC},
	// 		{Type: configs.NEWPID},
	// 		{Type: configs.NEWUSER},
	// 		{Type: configs.NEWNET},
	// 		{Type: configs.NEWCGROUP},
	// 	}),
	// 	Cgroups: &configs.Cgroup{
	// 		Name:   "test-container",
	// 		Parent: "system",
	// 		Resources: &configs.Resources{
	// 			MemorySwappiness: nil,
	// 			Devices:          devices,
	// 		},
	// 	},
	// 	MaskPaths: []string{
	// 		"/proc/kcore",
	// 		"/sys/firmware",
	// 	},
	// 	ReadonlyPaths: []string{
	// 		"/proc/sys", "/proc/sysrq-trigger", "/proc/irq", "/proc/bus",
	// 	},
	// 	Devices:  specconv.AllowedDevices,
	// 	Hostname: "testing",
	// 	Mounts: []*configs.Mount{
	// 		{
	// 			Source:      "proc",
	// 			Destination: "/proc",
	// 			Device:      "proc",
	// 			Flags:       defaultMountFlags,
	// 		},
	// 		{
	// 			Source:      "tmpfs",
	// 			Destination: "/dev",
	// 			Device:      "tmpfs",
	// 			Flags:       unix.MS_NOSUID | unix.MS_STRICTATIME,
	// 			Data:        "mode=755",
	// 		},
	// 		{
	// 			Source:      "devpts",
	// 			Destination: "/dev/pts",
	// 			Device:      "devpts",
	// 			Flags:       unix.MS_NOSUID | unix.MS_NOEXEC,
	// 			Data:        "newinstance,ptmxmode=0666,mode=0620,gid=5",
	// 		},
	// 		{
	// 			Device:      "tmpfs",
	// 			Source:      "shm",
	// 			Destination: "/dev/shm",
	// 			Data:        "mode=1777,size=65536k",
	// 			Flags:       defaultMountFlags,
	// 		},
	// 		{
	// 			Source:      "mqueue",
	// 			Destination: "/dev/mqueue",
	// 			Device:      "mqueue",
	// 			Flags:       defaultMountFlags,
	// 		},
	// 		{
	// 			Source:      "sysfs",
	// 			Destination: "/sys",
	// 			Device:      "sysfs",
	// 			Flags:       defaultMountFlags | unix.MS_RDONLY,
	// 		},
	// 	},
	// 	UidMappings: []configs.IDMap{
	// 		{
	// 			ContainerID: 0,
	// 			HostID:      1000,
	// 			Size:        65536,
	// 		},
	// 	},
	// 	GidMappings: []configs.IDMap{
	// 		{
	// 			ContainerID: 0,
	// 			HostID:      1000,
	// 			Size:        65536,
	// 		},
	// 	},
	// 	Networks: []*configs.Network{
	// 		{
	// 			Type:    "loopback",
	// 			Address: "127.0.0.1/0",
	// 			Gateway: "localhost",
	// 		},
	// 	},
	// 	Rlimits: []configs.Rlimit{
	// 		{
	// 			Type: unix.RLIMIT_NOFILE,
	// 			Hard: uint64(1025),
	// 			Soft: uint64(1025),
	// 		},
	// 	},
	// }
	// container, err := factory.Create("container-id", config)
	// if err != nil {
	// 	return
	// }
	// process := &libcontainer.Process{
	// 	Args:   []string{"/bin/bash"},
	// 	Env:    []string{"PATH=/bin"},
	// 	User:   "daemon",
	// 	Stdin:  os.Stdin,
	// 	Stdout: os.Stdout,
	// 	Stderr: os.Stderr,
	// 	Init:   true,
	// }

	// err = container.Run(process)
	// if err != nil {
	// 	container.Destroy()
	// 	return
	// }

	// // wait for the process to finish.
	// _, err = process.Wait()
	// if err != nil {
	// 	return
	// }

	// // destroy the container.
	// container.Destroy()
}
