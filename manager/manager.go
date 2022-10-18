package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"

	"github.com/rss/kit/exec"
	"github.com/rss/kit/pgen"
	"github.com/rss/kit/result"
	"github.com/rss/kit/trace"
	"github.com/rss/kit/util"
	"github.com/rss/kit/vm"
	"github.com/rss/kit/vm/vmimpl"
)

type ManagerUserConfig struct {

	// –––––––––––––––––––––––––––––––––––  Manager ––––––––––––––––––––––––––––––––––––––––––––

	// Instance name (used for identification and as GCE instance prefix).
	Name string `json:"name"`
	// Location of a working directory
	Workdir string `json:"workdir"`
	// List of syscalls to test (optional). For example:
	//	"enable_syscalls": [ "mmap", "openat$ashmem", "ioctl$ASHMEM*" ]
	EnabledSyscalls []string `json:"enable_syscalls,omitempty"`
	// List of system calls that should be treated as disabled (optional).
	DisabledSyscalls []string `json:"disable_syscalls,omitempty"`
	// Location of the syzkaller checkout, syz-manager will look
	// for binaries in bin subdir (does not have to be syzkaller checkout as
	// long as it preserves `bin` dir structure)
	Kit string `json:"kit"`

	// ––––––––––––––––––––––––––––––––––––– VM –––––––––––––––––––––––––––––––––––––––––––––

	// Location of the disk image file.
	Image string `json:"image,omitempty"`
	// Location (on the host machine) of a root SSH identity to use for communicating with
	// the virtual machine (may be empty for some VM types).
	SSHKey string `json:"sshkey,omitempty"`
	// SSH user ("root" by default).
	SSHUser string `json:"ssh_user,omitempty"`
	// VM-type-specific parameters.
	// Parameters for concrete types are in Config type in vm/TYPE/TYPE.go, e.g. vm/qemu/qemu.go.
	VM json.RawMessage `json:"vm"`
	// Refers to a directory. Optional.
	// Each VM will get a recursive copy of the files that are present in workdir_template.
	// VM config can then use these private copies as needed. The copy directory
	// can be referenced with "{{TEMPLATE}}" string. This is different from using
	// the files directly in that each instance will get own clean, private,
	// scratch copy of the files. Currently supported only for qemu_args argument
	// of qemu VM type. Use example:
	// Create a template dir with necessary files:
	// $ mkdir /mytemplatedir
	// $ truncate -s 64K /mytemplatedir/fd
	// Then specify the dir in the manager config:
	//	"workdir_template": "/mytemplatedir"
	// Then use these files in VM config:
	//	"qemu_args": "-fda {{TEMPLATE}}/fd"
	WorkdirTemplate string `json:"workdir_template"`
	// Create executor snapshot in given image.
	// Enable this if there is no snapshot in given image.
	// TODO: Create snapshot when there is no snapshot in image.
	CreateSnapshot bool `json:"create_snapshot"`

	// –––––––––––––––––––––– Profile && Test ––––––––––––––––––––––––
	// Run C programs
	CProg bool `json:"c_prog"`
	// Directory that contains program
	ProgDir string `json:"prog_dir"`
	// –––––––––––––––––––––– Profile Specific ––––––––––––––––––––––––
	// Directory to save all profile data.
	ProfileDir string `json:"profile_dir"`
	// –––––––––––––––––––––– Test Specific ––––––––––––––––––––––––
	// Trace directory
	TraceDir string `json:"trace_dir"`
	// Prediction path
	Pred string `json:"pred"`
	// Result file
	ResultDir string `json:"result_dir"`

	// Server mode
	Server bool `json:"server"`
	// Server address
	ServerAddr string `json:"server_addr"`
	// Client mode
	Client             bool `json:"client"`
	ClientTimeoutScale int  `json:"client_timeout_scale"`
}

type ManagerConfig struct {
	ManagerUserConfig

	// ––––––––––––––––––––––––––––––––––––– Magager –––––––––––––––––––––––––––––––––––––––––––––
	PrintInterval time.Duration `json:"print_interval"`

	// ––––––––––––––––––––––––––––––––––––– VM –––––––––––––––––––––––––––––––––––––––––––––
	VMType         string           `json:"vm_type"`
	TargetOS       string           `json:"target_os"`
	TargetArch     string           `json:"target_arch"`
	TargetVMArch   string           `json:"target_vm_arch"`
	ExecutordBin   string           `json:"executord_bin"`
	ExecutorcpdBin string           `json:"executorcpd_bin"`
	ExecutorBin    string           `json:"executor_bin"`
	CProgHeader    string           `json:"cprog_header"`
	Timeouts       targets.Timeouts `json:"-"`
	Target         *prog.Target     `json:"-"`
	SysTarget      *targets.Target  `json:"-"`
	ProfileTimeout time.Duration    `json:"-"`
	TestTimeout    time.Duration    `json:"-"`
}

type ManagerStat struct {
	StatTest    uint64
	StatTimeout uint64
	StatHanged  uint64
	StatExecCnt uint64
	StatResult  uint64
	StatTotRes  uint64
}

func (s *ManagerStat) SafeLoad() *ManagerStat {
	c := &ManagerStat{
		StatTest:    atomic.LoadUint64(&s.StatTest),
		StatTimeout: atomic.LoadUint64(&s.StatTimeout),
		StatHanged:  atomic.LoadUint64(&s.StatHanged),
		StatExecCnt: atomic.LoadUint64(&s.StatExecCnt),
		StatResult:  atomic.LoadUint64(&s.StatResult),
		StatTotRes:  atomic.LoadUint64(&s.StatTotRes),
	}
	return c
}

type Manager struct {
	cfg           *ManagerConfig
	muvmpool      sync.Mutex
	vmpool        *vm.Pool
	vmenv         *vmimpl.Env
	progTarget    *prog.Target
	progGen       pgen.ProgGenerator
	progCh        chan *pgen.ProgGen
	profileTmpDir string
	pairGen       pgen.ProgPairGenerator
	pairCh        chan *pgen.ProgPair
	resultTmpDir  string
	syscallsTable map[*prog.Syscall]bool
	traceMuNum    int
	traceMu       []sync.Mutex
	server        *rpctype.RPCServer
	client        *ManagerClient
	stat          ManagerStat
	clientInfoMu  sync.Mutex
	clientInfo    map[string]*RPCClientInfo
	workerWg      *sync.WaitGroup
}

type Worker struct {
	mgr   *Manager
	wg    *sync.WaitGroup
	index int
}

var (
	flagConfig  = flag.String("config", "", "config file")
	flagDebug   = flag.Bool("debug", false, "debug mode")
	flagProfile = flag.Bool("profile", false, "profile test program")
	flagTest    = flag.Bool("test", false, "run test cases")
)

func defaultManagerConfig() *ManagerConfig {
	// now we only focus on linux/amd64/qemu
	return &ManagerConfig{
		ManagerUserConfig: ManagerUserConfig{
			SSHUser: "root",
		},
		PrintInterval:  5 * time.Second,
		VMType:         "qemu",
		TargetOS:       "linux",
		TargetArch:     "amd64",
		TargetVMArch:   "amd64",
		ProfileTimeout: 40000 * time.Millisecond,
		TestTimeout:    80000 * time.Millisecond,
	}
}

func (mgr *Manager) initConfig(configPath string) {
	var cfg *ManagerConfig
	var data, cfgstr []byte
	var err error

	// default config
	cfg = defaultManagerConfig()

	// load user config
	data, err = ioutil.ReadFile(configPath)
	if err != nil {
		log.Fatalf("failed to read config file: %v", err)
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		log.Fatalf("failed to parse config file: %v", err)
	}

	// complete final config
	cfg.Target, err = prog.GetTarget(cfg.TargetOS, cfg.TargetArch)
	if err != nil {
		log.Fatalf("failed to get target: %v", err)
	}
	cfg.SysTarget = targets.Get(cfg.TargetOS, cfg.TargetArch)
	cfg.Timeouts = cfg.SysTarget.Timeouts(2)
	// TODO: config check function
	cfg.ExecutorBin = filepath.Join(cfg.Kit, "bin", "executor")
	cfg.ExecutordBin = filepath.Join(cfg.Kit, "bin", "executord")
	cfg.ExecutorcpdBin = filepath.Join(cfg.Kit, "bin", "executorcd")
	cfg.CProgHeader = filepath.Join(cfg.Kit, "executor", "comm.h")

	cfgstr, err = json.MarshalIndent(cfg, "", "\t")
	if err != nil {
		log.Fatalf("cannot print config: %v", err)
	}
	log.Logf(0, "config:\n%s", string(cfgstr))

	mgr.cfg = cfg
}

func (mgr *Manager) initServer() {
	if mgr.cfg.Server {
		var err error
		mgr.clientInfo = map[string]*RPCClientInfo{}
		mgr.server, err = NewManagerServer(mgr.cfg.ServerAddr, mgr)
		if err != nil {
			log.Fatalf("cannot init server: %v", err)
		}
		go mgr.server.Serve()
		log.Logf(0, "server started, listening on address %v", mgr.cfg.ServerAddr)
	}
}

func (mgr *Manager) initClient() {
	if mgr.cfg.Client {
		var err error
		mgr.client, err = NewManagerClient(mgr.cfg.ServerAddr, time.Duration(mgr.cfg.ClientTimeoutScale))
		if err != nil {
			log.Fatalf("cannot init client: %v", err)
		}
		log.Logf(0, "server[%v] connected", mgr.cfg.ServerAddr)
		go func() {
			for {
				mgr.client.NewClientInfo(mgr.cfg.Name, mgr.stat.SafeLoad())
				time.Sleep(ClientHeartbeatInterval)
			}
		}()
	}
}

func (mgr *Manager) initVMPool(debug bool) {
	var err error
	var cfg *ManagerConfig
	var env *vmimpl.Env
	var pool *vm.Pool

	cfg = mgr.cfg
	env = &vmimpl.Env{
		Name:     cfg.Name,
		OS:       cfg.TargetOS,
		Arch:     cfg.TargetVMArch,
		Workdir:  cfg.Workdir,
		Image:    cfg.Image,
		SSHKey:   cfg.SSHKey,
		SSHUser:  cfg.SSHUser,
		Timeouts: cfg.Timeouts,
		Debug:    debug,
		Config:   cfg.VM,
		Template: cfg.WorkdirTemplate,
		CommNum:  exec.CommNum,
	}

	err = os.MkdirAll(cfg.Workdir, os.ModePerm)
	if err != nil {
		log.Logf(0, "cannot create workdir: %v", err)
	}
	// TODO: handle SIGINT signal
	if !cfg.Client && cfg.CreateSnapshot {
		pool, err = vm.Create(cfg.VMType, env)
		if err != nil {
			log.Fatalf("failed to start vm pool: %v", err)
		}
		snapshotImage := path.Join(mgr.cfg.Workdir, "copy-"+path.Base(cfg.Image))
		os.Remove(snapshotImage)
		log.Logf(0, "creating snapshot at %v...", snapshotImage)
		inst, err := pool.Create(0)
		if err != nil {
			log.Fatalf("cannot start vm to creat snapshot: %v", err)
		}
		if *flagTest && mgr.cfg.CProg {
			err = exec.CreateCProgSnapshot(inst, cfg.VMType, inst.CommType(), cfg.ExecutorcpdBin, cfg.CProgHeader, debug)
			if err != nil {
				inst.Close()
				log.Fatalf("cannot create C program executor snapshot: %v", err)
			}
		} else {
			// let executord's exec.exec() function increase slowdown for memory trace function, so use small slowdown here
			// Disable code coverage collection since executor doesn't have priviledge under current test setting.
			err = exec.CreateSnapshot(inst, cfg.VMType, inst.CommType(), cfg.ExecutordBin, cfg.ExecutorBin, false, false, 2, debug)
			if err != nil {
				inst.Close()
				log.Fatalf("cannot create snapshot: %v", err)
			}
		}
		err = os.Link(inst.Image(), snapshotImage)
		if err != nil {
			inst.Close()
			log.Fatalf("cannot link snapshot image %v to %v: %v", inst.Image(), snapshotImage, err)
		}
		inst.Close()
		env.Image = snapshotImage
		snapshotImageAbs, err := filepath.Abs(snapshotImage)
		if err != nil {
			util.GFatalf("cannot get absolute path for snapshot image: %v", err)
		}
		err = ioutil.WriteFile(path.Join(mgr.cfg.Workdir, "snapshot_image"), []byte(snapshotImageAbs), 0666)
		if err != nil {
			util.GFatalf("cannot log profile dir: %v", err)
		}

	} else if cfg.Client {
		log.Logf(0, "downloading VM image from server...")
		imgData, keyData, err := mgr.client.GetVMImage()
		if err != nil {
			log.Fatalf("cannot download VM image from server: %v", err)
		}
		// Assume qcow2
		imgPath := path.Join(mgr.cfg.Workdir, "download_img.qcow2")
		err = ioutil.WriteFile(imgPath, imgData, 0666)
		if err != nil {
			log.Fatalf("cannot save VM image: %v", err)
		}
		keyPath := path.Join(mgr.cfg.Workdir, "download_key.id_rsa")
		err = ioutil.WriteFile(keyPath, keyData, 0600)
		if err != nil {
			log.Fatalf("cannot save SSH key: %v", err)
		}
		log.Logf(0, "VM image downloaded!")
		env.Image = imgPath
		env.SSHKey = keyPath
	}
	env.LoadVM = true
	mgr.vmenv = env
	mgr.vmpool, err = vm.Create(cfg.VMType, env)
	if err != nil {
		log.Fatalf("cannot start new vm pool using existing VM snapshot: %v", err)
	}

	log.Logf(0, "snapshot image at %v", env.Image)
	// TODO: need reporter to detect non-semantic bugs?
}

func (mgr *Manager) initMisc() {
	var err error

	mgr.progTarget, err = prog.GetTarget(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		log.Fatalf("cannot get program target: %v", err)
	}
	// build syscall whitelist
	syscallsIDs, err := mgrconfig.ParseEnabledSyscalls(mgr.progTarget, mgr.cfg.EnabledSyscalls, mgr.cfg.DisabledSyscalls)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse enabled syscalls: %v\n", err)
		os.Exit(1)
	}
	mgr.syscallsTable = make(map[*prog.Syscall]bool)
	for _, id := range syscallsIDs {
		mgr.syscallsTable[mgr.progTarget.Syscalls[id]] = true
	}

	if *flagProfile {
		mgr.progGen, err = pgen.InitFileProgGenerator(mgr.progTarget, mgr.cfg.ProgDir)
		if err != nil {
			log.Fatalf("cannot init file program generator: %v", err)
		}
		// TODO: support multiple producers
		mgr.progCh = make(chan *pgen.ProgGen, 40)
		go func() {
			for {
				prog, err := mgr.progGen.Generate()
				if (prog == nil) && (err == nil) {
					close(mgr.progCh)
					break
				} else if err != nil {
					util.GFatalf("program generator error: %v", err)
				}
				if !pgen.ProgramCheck(prog.P, mgr.syscallsTable) {
					log.Logf(0, "Drop program %v:\n%v", prog.Meta.Name, string(prog.P.Serialize()))
					continue
				}
				mgr.progCh <- prog
			}
		}()
		err := os.MkdirAll(mgr.cfg.ProfileDir, os.ModePerm)
		if err != nil {
			util.GFatalf("cannot create dir: %v", err)
		}
		dir, err := ioutil.TempDir(mgr.cfg.ProfileDir, "profile-"+time.Now().Format("2006_01_02_15_04_05")+"-*")
		if err != nil {
			util.GFatalf("cannot create profile dir: %v", err)
		}
		log.Logf(0, "create profile dir at %v", dir)
		mgr.profileTmpDir = dir
		dirAbs, err := filepath.Abs(dir)
		if err != nil {
			util.GFatalf("cannot get absolute path for profile directory: %v", err)
		}
		err = ioutil.WriteFile(path.Join(mgr.cfg.Workdir, "profile_dir"), []byte(dirAbs), 0666)
		if err != nil {
			util.GFatalf("cannot log profile dir: %v", err)
		}

	} else if *flagTest {
		mgr.traceMuNum = 500
		for i := 0; i < mgr.traceMuNum; i++ {
			mgr.traceMu = append(mgr.traceMu, sync.Mutex{})
		}
		if mgr.cfg.Client {
			mgr.pairGen = InitClientTestGenerator(mgr.progTarget, mgr.cfg.ProgDir, mgr.client, 500)
		} else {
			if mgr.cfg.CProg {
				mgr.pairGen, err = pgen.InitReproTestGenerator(mgr.cfg.ProgDir, mgr.cfg.Pred)
				if err != nil {
					log.Fatalf("cannot init repro program pair generator: %v", err)
				}
			} else {
				mgr.pairGen, err = pgen.InitTestGenerator(mgr.progTarget, mgr.cfg.ProgDir, mgr.cfg.Pred)
				if err != nil {
					log.Fatalf("cannot init program pair generator: %v", err)
				}
			}
		}
		mgr.pairCh = make(chan *pgen.ProgPair, 500)
		go func() {
			for {
				pair, err := mgr.pairGen.Generate()
				if (pair == nil) && (err == nil) {
					close(mgr.pairCh)
					break
				} else if err != nil {
					util.GFatalf("program pair generator error: %v", err)
				}
				mgr.pairCh <- pair
			}
		}()
		if !mgr.cfg.Client {
			err := os.MkdirAll(mgr.cfg.ResultDir, os.ModePerm)
			if err != nil {
				util.GFatalf("cannot create dir: %v", err)
			}
			dir, err := ioutil.TempDir(mgr.cfg.ResultDir, "result-"+time.Now().Format("2006_01_02_15_04_05")+"-*")
			if err != nil {
				util.GFatalf("cannot create result dir: %v", err)
			}
			log.Logf(0, "create result dir at %v", dir)
			mgr.resultTmpDir = dir
			dirAbs, err := filepath.Abs(dir)
			if err != nil {
				util.GFatalf("cannot get absolute path for result directory: %v", err)
			}
			err = ioutil.WriteFile(path.Join(mgr.cfg.Workdir, "result_dir"), []byte(dirAbs), 0666)
			if err != nil {
				util.GFatalf("cannot log result dir: %v", err)
			}
		}
	}
}

func (mgr *Manager) updateTestStat(timeout, hanged bool) {
	atomic.AddUint64(&mgr.stat.StatTest, 1)
	if timeout {
		atomic.AddUint64(&mgr.stat.StatTimeout, 1)
	} else if hanged {
		atomic.AddUint64(&mgr.stat.StatHanged, 1)
	}
}

func (mgr *Manager) updateTotResults() {
	atomic.AddUint64(&mgr.stat.StatTotRes, 1)
}

func (fuz *Worker) newResult(test *pgen.ProgPair, aProgMini *prog.Prog, aCallDiag, vCallDiag []int, testIdx, clsIdx, clsMemIdx, clsMemAProgIdx, clsMemVProgIdx int, aPredPC, aPredAddr, vPredPC, vPredAddr uint64, aPredAddrLen, vPredAddrLen uint8, interleave bool, vPause uint8, aExecFlag, vExecFlag uint64, timeout, aProgHanged, vProgHanged bool, adiff, vdiff []*trace.SCTraceDiff, aProgSCTrace, aProgMiniSCTrace, vProgSCTrace, aProgPrevSCTrace, vProgPrevSCTrace *trace.ProgSCTrace) {
	res := result.NewTestResult(test, aProgMini, aCallDiag, vCallDiag, testIdx, clsIdx, clsMemIdx, clsMemAProgIdx, clsMemVProgIdx, aPredPC, aPredAddr, vPredPC, vPredAddr, aPredAddrLen, vPredAddrLen, interleave, vPause, aExecFlag, vExecFlag, timeout, aProgHanged, vProgHanged, adiff, vdiff, aProgSCTrace, aProgMiniSCTrace, vProgSCTrace, aProgPrevSCTrace, vProgPrevSCTrace)
	log.Logf(0, "new result: %v-%v, interleave = %v, vPause = %v", res.AProgName, res.VProgName, res.Interleave, res.VPause)
	if !fuz.mgr.cfg.Client {
		err := result.SerializeTestResult(fuz.mgr.resultTmpDir, res)
		if err != nil {
			util.GFatalf("cannot save new result: %v", err)
		}
	} else {
		err := fuz.mgr.client.NewTestResult(res)
		if err != nil {
			util.GFatalf("cannot upload new result: %v", err)
		}
	}
	atomic.AddUint64(&fuz.mgr.stat.StatResult, 1)
}

func SCStrCheck(SCStrTest []string, SCStrExpect [][]string) (equal bool, SCTraceTest, SCTraceExpect *trace.ProgSCTrace, diff []*trace.SCTraceDiff, noMatch bool, err error) {
	SCTraceTest, err = trace.ParseSCTrace(SCStrTest)
	if err != nil {
		err = fmt.Errorf("cannot parse test syscall trace string: %v", err)
		return false, nil, nil, nil, false, err
	}
	SCTraceExpect, err = trace.ParseSCTrace(SCStrExpect[0])
	if err != nil {
		err = fmt.Errorf("cannot parse expect syscall trace 0 string: %v", err)
		return false, nil, nil, nil, false, err
	}
	for _, scStr := range SCStrExpect[1:] {
		SCTraceExpectTmp, err := trace.ParseSCTrace(scStr)
		if err != nil {
			err = fmt.Errorf("cannot parse expect syscall trace 0 string: %v", err)
			return false, nil, nil, nil, false, err
		}
		noMatch, _ = trace.ProgSCTraceNDUpdate(SCTraceExpect, SCTraceExpectTmp)
		if noMatch {
			break
		}
	}
	if noMatch {
		return false, nil, nil, nil, true, nil
	}
	equal, diff = trace.ProgSCTraceNDEqual(SCTraceExpect, SCTraceTest)
	return
}

func profileMemTrace(e *exec.ExecutorMaster, tr *trace.TraceInfo, dir string, p *prog.Prog, flag exec.ExecFlags, timeoutDur time.Duration) (timeout bool, hanged bool, err error) {
	var test *exec.Test
	emptyP := &prog.Prog{}
	if tr.Attack {
		test = &exec.Test{
			A: &exec.ExecData{
				Opts: exec.ExecOpts{Flags: flag | exec.FlagMemtrace},
				P:    p,
			},
			V: &exec.ExecData{
				Opts: exec.ExecOpts{Flags: flag},
				P:    emptyP,
			},
		}
	} else {
		test = &exec.Test{
			A: &exec.ExecData{
				Opts: exec.ExecOpts{Flags: flag},
				P:    emptyP,
			},
			V: &exec.ExecData{
				Opts: exec.ExecOpts{Flags: flag | exec.FlagMemtrace},
				P:    p,
			},
		}
	}
	testRep, timeout, err := e.Run(test, timeoutDur)
	if err != nil {
		err = fmt.Errorf("cannot run test program: %v", err)
		return
	}
	if timeout {
		tr.Timeout = true
		return
	}
	var callInfo []exec.CallInfo
	if tr.Attack {
		callInfo = testRep.A.Info.Calls
		hanged = testRep.A.Hanged
	} else {
		callInfo = testRep.V.Info.Calls
		hanged = testRep.V.Hanged
	}
	if hanged {
		return
	}
	err = trace.SaveMemtrace(tr, dir, callInfo)
	if err != nil {
		err = fmt.Errorf("cannot save memory trace: %v", err)
		return
	}
	return
}

func profileSCTrace(e *exec.ExecutorMaster, test *exec.Test, timeoutDur time.Duration) (aSCRaw []string, vSCRaw []string, timeout bool, aHanged, vHanged bool, aCallInfo, vCallInfo []exec.CallInfo, err error) {
	test.A.Opts.Flags |= exec.FlagSctrace
	test.V.Opts.Flags |= exec.FlagSctrace
	testRep, timeout, err := e.Run(test, timeoutDur)
	if err != nil {
		err = fmt.Errorf("cannot run test program: %v", err)
		goto out
	}
	if timeout {
		goto out
	}
	aHanged = testRep.A.Hanged
	vHanged = testRep.V.Hanged
	aCallInfo = testRep.A.Info.Calls
	vCallInfo = testRep.V.Info.Calls
	// collect victim trace
	for i := 0; i < len(testRep.V.Info.Calls); i++ {
		s := testRep.V.Info.Calls[i].Sctrace
		t := make([]byte, len(s))
		copy(t, s)
		vSCRaw = append(vSCRaw, string(t))
	}
	// collect attack trace
	for i := 0; i < len(testRep.A.Info.Calls); i++ {
		s := testRep.A.Info.Calls[i].Sctrace
		t := make([]byte, len(s))
		copy(t, s)
		aSCRaw = append(aSCRaw, string(t))
	}
out:
	return
}

func identifyNondet(target *prog.Target, e *exec.ExecutorMaster, t *exec.Test, aExecTimeMs uint32, vProfileSCTrace, vTestSCTrace *trace.ProgSCTrace, maxTime time.Duration, r int) (savedVSCRaw [][]string, vTestSCTraceEqual bool, vTestSCTraceDiff []*trace.SCTraceDiff, err error) {
	// generate sleep programs
	spArr := []*prog.Prog{}

	// two types of timeout:
	// 1. attacker program monitor is down
	// 2. attacker program blocks, but attacker program monitor is alive
	// simulates above types
	sp, err := getNanoSleepProg(0, true, target)
	if err != nil {
		return nil, false, nil, fmt.Errorf("get sleep program: %v", err)
	}
	spArr = append(spArr, sp)

	// 1st sleep program
	sp, err = getNanoSleepProg(aExecTimeMs, false, target)
	if err != nil {
		return nil, false, nil, fmt.Errorf("get sleep program: %v", err)
	}
	spArr = append(spArr, sp)
	sp, _ = getNanoSleepProg(1234, false, target)
	spArr = append(spArr, sp)
	sp, _ = getNanoSleepProg(23, false, target)
	spArr = append(spArr, sp)
	downRange := uint32(r)
	upRange := uint32(r)
	if downRange > aExecTimeMs {
		downRange = aExecTimeMs
	}
	// 2nd sleep program
	sp, _ = getNanoSleepProg(aExecTimeMs-uint32(rand.Intn(int(downRange))), false, target)
	spArr = append(spArr, sp)
	// 3rd sleep program
	sp, _ = getNanoSleepProg(aExecTimeMs+uint32(rand.Intn(int(upRange))), false, target)
	spArr = append(spArr, sp)

	for _, sp := range spArr {
		var vNondetSCRaw []string
		var vSCTraceNonDet *trace.ProgSCTrace
		nonDetTest := &exec.Test{
			A: &exec.ExecData{
				Opts: t.A.Opts,
				P:    sp,
			},
			V: &exec.ExecData{
				Opts: t.V.Opts,
				P:    t.V.P,
			},
		}
		_, vNondetSCRaw, _, _, _, _, _, err = profileSCTrace(e, nonDetTest, maxTime)
		if err != nil {
			return
		}
		vSCTraceNonDet, err = trace.ParseSCTrace(vNondetSCRaw)
		if err != nil {
			return nil, false, nil, fmt.Errorf("cannot parse nondet victim syscall trace: %v", err)
		}
		noMatch, update := trace.ProgSCTraceNDUpdate(vProfileSCTrace, vSCTraceNonDet)
		if noMatch {
			// drop these traces
			// TODO: serialize drop operations
			if len(vProfileSCTrace.Traces) > len(vSCTraceNonDet.Traces) {
				vProfileSCTrace.Traces = vProfileSCTrace.Traces[:len(vSCTraceNonDet.Traces)]
			}
			if len(vProfileSCTrace.Raw) > len(vSCTraceNonDet.Raw) {
				vProfileSCTrace.Raw = vProfileSCTrace.Raw[:len(vSCTraceNonDet.Raw)]
			}
		} else if update {
			savedVSCRaw = append(savedVSCRaw, vNondetSCRaw)
		}
		if vTestSCTraceEqual, vTestSCTraceDiff = trace.ProgSCTraceNDEqual(vProfileSCTrace, vTestSCTrace); vTestSCTraceEqual {
			return
		}
	}
	return
}

func diagnose(e *exec.ExecutorMaster, t *exec.Test, vProfileSCTrace *trace.ProgSCTrace, testDiff []*trace.SCTraceDiff, maxTime time.Duration) (aCall []int, vCall []int) {
	apc := t.A.P.Clone()
	vCallIdxMap := map[int]bool{}
	vCallIdxArr := []int{}
	for _, d := range testDiff {
		vCallIdxMap[d.CallIdx] = true
	}
	for c := range vCallIdxMap {
		vCallIdxArr = append(vCallIdxArr, c)
	}
	// log.Logf(0, "orignal interfered victim call", vCallIdxArr)
	for i := len(t.A.P.Calls) - 1; i >= 0; i-- {
		// log.Logf(0, "remove call %d..", i)
		apc.RemoveCall(i)
		miniTest := &exec.Test{
			A: &exec.ExecData{
				P:    apc,
				Opts: t.A.Opts,
			},
			V: &exec.ExecData{
				P:    t.V.P,
				Opts: t.V.Opts,
			},
		}
		_, vSCRaw, _, _, _, _, _, err := profileSCTrace(e, miniTest, maxTime)
		if err != nil {
			continue
		}
		vSCTrace, err := trace.ParseSCTrace(vSCRaw)
		if err != nil {
			continue
		}
		_, reason := trace.ProgSCTraceNDEqual(vProfileSCTrace, vSCTrace)
		newVCallIdxMap := map[int]bool{}
		newVCallIdxArr := []int{}
		for _, r := range reason {
			newVCallIdxMap[r.CallIdx] = true
		}
		for c := range newVCallIdxMap {
			newVCallIdxArr = append(newVCallIdxArr, c)
		}
		// log.Logf(0, "new interfered victim call", newVCallIdxArr)
		vCallIdxMin := 10000
		// substract
		testVCallNext := []int{}
		for _, d := range vCallIdxArr {
			// log.Logf(0, "search call %d...", d)
			found := false
			for _, r := range newVCallIdxArr {
				if d == r {
					// log.Logf(0, "found!")
					found = true
					break
				}
			}
			if !found {
				// log.Logf(0, "not found!")
				if vCallIdxMin > d {
					vCallIdxMin = d
				}
			} else {
				testVCallNext = append(testVCallNext, d)
			}
		}
		// log.Logf(0, "vCallMin = %v", vCallIdxMin)
		if vCallIdxMin != 10000 {
			aCall = append(aCall, i)
			vCall = append(vCall, vCallIdxMin)
		}
		// log.Logf(0, "testVCallNext = %v", testVCallNext)
		if len(testVCallNext) == 0 {
			break
		}
		vCallIdxArr = testVCallNext

	}
	return
}

// func minimizeAttackProg(e *exec.ExecutorMaster, t *exec.Test, vProfileSCTrace *trace.ProgSCTrace, testDiff []*trace.SCTraceDiff, maxTime time.Duration) (*prog.Prog, *trace.ProgSCTrace) {
// 	miniAP, _ := prog.Minimize(t.A.P.Clone(), -1, false, func(miniAP *prog.Prog, rmIdx int) bool {
// 		miniTest := &exec.Test{
// 			A: &exec.ExecData{
// 				P:    miniAP,
// 				Opts: t.A.Opts,
// 			},
// 			V: &exec.ExecData{
// 				P:    t.V.P,
// 				Opts: t.V.Opts,
// 			},
// 		}
// 		_, vSCRaw, _, _, _, _, _, err := profileSCTrace(e, miniTest, maxTime)
// 		if err != nil {
// 			return false
// 		}
// 		vSCTrace, err := trace.ParseSCTrace(vSCRaw)
// 		if err != nil {
// 			return false
// 		}
// 		equal, reason := trace.ProgSCTraceNDEqual(vProfileSCTrace, vSCTrace)
// 		if equal {
// 			return false
// 		} else {
// 			// We only checks if the first diff is reproduced
// 			// TODO: should we consider other diffs?
// 			if *reason[0] == *testDiff[0] {
// 				return true
// 			} else {
// 				return false
// 			}
// 		}
// 	})
// 	miniTest := &exec.Test{
// 		A: &exec.ExecData{
// 			P:    miniAP,
// 			Opts: t.A.Opts,
// 		},
// 		V: &exec.ExecData{
// 			P:    t.V.P,
// 			Opts: t.V.Opts,
// 		},
// 	}
// 	aMiniSCRaw, _, _, _, _, _, _, _ := profileSCTrace(e, miniTest, maxTime)
// 	aMiniSCTrace, _ := trace.ParseSCTrace(aMiniSCRaw)
// 	return miniAP, aMiniSCTrace
// }

func getNanoSleepProg(ms uint32, killNotifyFd bool, target *prog.Target) (*prog.Prog, error) {
	s := ms / 1000
	ns := (ms % 1000) * 1000000
	progStr := "nanosleep(&(0x7f0000000140)={" + fmt.Sprintf("0x%x, 0x%x", s, ns) + "}, 0x0)\n"
	if killNotifyFd {
		// hardcode the executor's notify file descriptor
		progStr += "close(0xec)\n"
	}
	nanoSleepProg, err := target.Deserialize(
		[]byte(progStr),
		prog.NonStrict)

	if err != nil {
		return nil, err
	}
	return nanoSleepProg, err
}

func (fuz *Worker) run(debug bool) {
	var inst *vm.Instance
	var e *exec.ExecutorMaster
	var err error

	log.Logf(0, "worker %v starting...", fuz.index)
	fuz.mgr.muvmpool.Lock()
	inst, err = fuz.mgr.vmpool.Create(fuz.index)
	fuz.mgr.muvmpool.Unlock()
	if err != nil {
		log.Logf(0, "worker %v cannot create vm: %v", fuz.index, err)
		return
	}

	e = exec.InitExecutorMaster(fuz.index, inst, fuz.mgr.cfg.CProg, debug)
	defer e.Close()

	log.Logf(0, "worker %v started", fuz.index)
	atomic.AddUint64(&fuz.mgr.stat.StatExecCnt, 1)

	if err != nil {
		log.Logf(0, "worker %v cannot deserialize time program: %v", fuz.index, err)
		return
	}

	for {
		if *flagProfile {
			testP := <-fuz.mgr.progCh
			if testP == nil {
				break
			}

			p := testP.P
			emptyProg := &prog.Prog{}
			execFlag := exec.ExecFlags(0)
			aSCTest := &exec.Test{
				A: &exec.ExecData{
					Opts: exec.ExecOpts{Flags: execFlag},
					P:    p,
				},
				V: &exec.ExecData{
					Opts: exec.ExecOpts{Flags: execFlag},
					P:    emptyProg,
				},
			}
			vSCTest := &exec.Test{
				A: &exec.ExecData{
					Opts: exec.ExecOpts{Flags: execFlag},
					P:    emptyProg,
				},
				V: &exec.ExecData{
					Opts: exec.ExecOpts{Flags: execFlag},
					P:    p,
				},
			}

			var aTraceInfo, vTraceInfo *trace.TraceInfo
			var aSCRawArr, vSCRawArr [][]string
			var scRaw []string

			aTraceInfo = trace.NewTraceInfo(testP.Meta.Name, true, false, false)
			vTraceInfo = trace.NewTraceInfo(testP.Meta.Name, false, false, false)

			// collect attacker memory trace
			timeout, hanged, err := profileMemTrace(e, aTraceInfo, fuz.mgr.profileTmpDir, p, execFlag, fuz.mgr.cfg.ProfileTimeout)
			if err != nil {
				goto handle_err
			}
			fuz.mgr.updateTestStat(timeout, hanged)
			if timeout {
				// TODO: think about this
				goto handle_timeout
			}
			if hanged {
				// TODO: think about this
				goto handle_hanged
			}

			// collect attacker syscall trace
			scRaw, _, timeout, hanged, _, _, _, err = profileSCTrace(e, aSCTest, fuz.mgr.cfg.ProfileTimeout)
			if err != nil {
				err = fmt.Errorf("cannot profile syscall trace: %v", err)
				goto handle_err
			}
			if timeout {
				goto handle_timeout
			}
			if hanged {
				goto handle_hanged
			}
			aSCRawArr = append(aSCRawArr, scRaw)
			fuz.mgr.updateTestStat(timeout, hanged)
			err = trace.SaveSCTrace(aTraceInfo, fuz.mgr.profileTmpDir, aSCRawArr)
			if err != nil {
				util.GFatalf("worker %v cannot save sc trace: %v", fuz.index, err)
			}

			// collect victim memory trace
			timeout, hanged, err = profileMemTrace(e, vTraceInfo, fuz.mgr.profileTmpDir, p, execFlag, fuz.mgr.cfg.ProfileTimeout)
			if err != nil {
				// TODO: think about this
				goto handle_err
			}
			fuz.mgr.updateTestStat(timeout, hanged)
			if timeout {
				// TODO: think about this
				goto handle_timeout
			}
			if hanged {
				// TODO: think about this
				goto handle_hanged
			}

			// collect victim syscall trace
			_, scRaw, timeout, _, hanged, _, _, err = profileSCTrace(e, vSCTest, fuz.mgr.cfg.ProfileTimeout)
			if err != nil {
				err = fmt.Errorf("cannot profile syscall trace: %v", err)
				goto handle_err
			}
			if timeout {
				goto handle_timeout
			}
			if hanged {
				goto handle_hanged
			}
			vSCRawArr = append(vSCRawArr, scRaw)
			fuz.mgr.updateTestStat(timeout, hanged)
			err = trace.SaveSCTrace(vTraceInfo, fuz.mgr.profileTmpDir, vSCRawArr)
			if err != nil {
				util.GFatalf("worker %v cannot save sc trace: %v", fuz.index, err)
			}

			goto next

		handle_hanged:
			log.Logf(0, "fuz %v hanged on %v program:\n%v", fuz.index, testP.Meta.Name, string(p.Serialize()))
			goto next
		handle_timeout:
			log.Logf(0, "fuz %v timeout on %v program:\n%v", fuz.index, testP.Meta.Name, string(p.Serialize()))
			goto next
		handle_err:
			log.Logf(0, "fuz %v profile %v program error: %v\n%v", fuz.index, testP.Meta.Name, err, string(p.Serialize()))
			goto next
		next:
			err = trace.SaveTraceInfo(aTraceInfo, fuz.mgr.profileTmpDir)
			if err != nil {
				util.GFatalf("worker %v cannot save trace info: %v", fuz.index, err)
			}
			err = trace.SaveTraceInfo(vTraceInfo, fuz.mgr.profileTmpDir)
			if err != nil {
				util.GFatalf("worker %v cannot save trace info: %v", fuz.index, err)
			}

		} else if *flagTest && fuz.mgr.cfg.CProg {
			testP := <-fuz.mgr.pairCh
			if testP == nil {
				break
			}
			// Profile w/o the attacker program
			pt := &exec.CTest{
				A:     testP.A.CP,
				V:     testP.V.CP,
				SkipA: true,
			}
			r, timeout, err := e.RunCTest(pt, 5*time.Second)
			if timeout {
				log.Logf(0, "profile victim trace %v w/o attacker timeout", pt.V.Meta.Name)
				continue
			}
			if err != nil {
				util.GFatalf("cannot profile victim trace w/o attacker: %v", err)
			}
			log.Logf(0, "victim %v trace w/o attacker program: %v", pt.V.Meta.Name, r.VSCTrace)
			// Profile w/ the attacke program
			t := &exec.CTest{
				A:     testP.A.CP,
				V:     testP.V.CP,
				SkipA: false,
			}
			rr, timeout, err := e.RunCTest(t, 5*time.Second)
			if timeout {
				log.Logf(0, "profile victim trace %v w/ attacker timeout", pt.V.Meta.Name)
				continue
			}
			if err != nil {
				util.GFatalf("cannot profile victim trace w attacker: %v", err)
			}
			log.Logf(0, "victim %v trace w attacker program: %v", pt.V.Meta.Name, rr.VSCTrace)
			// write result
			resName := strings.TrimSuffix(t.A.Meta.Name, filepath.Ext(t.A.Meta.Name)) + "_" + strings.TrimSuffix(t.V.Meta.Name, filepath.Ext(t.V.Meta.Name))
			err = ioutil.WriteFile(path.Join(fuz.mgr.resultTmpDir, resName), []byte(r.VSCTrace+"\n"+rr.VSCTrace), 0666)
			if err != nil {
				util.GFatalf("cannot write result: %v", err)
			}
		} else if *flagTest {

			// get test
			testP := <-fuz.mgr.pairCh
			if testP == nil {
				break
			}
			// run test
			aExecFlagBase := exec.ExecFlags(0)
			vExecFlagBase := exec.ExecFlags(0)
			test := &exec.Test{
				A: &exec.ExecData{
					Opts: exec.ExecOpts{Flags: aExecFlagBase},
					P:    testP.A.P,
				},
				V: &exec.ExecData{
					Opts: exec.ExecOpts{Flags: vExecFlagBase},
					P:    testP.V.P,
				},
			}
			aSCRaw, vSCRaw, timeout, aHanged, vHanged, aCallInfo, _, err := profileSCTrace(e, test, fuz.mgr.cfg.TestTimeout)
			if err != nil {
				log.Logf(0, "worker %v cannot test %v - %v proggram : %v", fuz.index, testP.A.Meta.Name, testP.V.Meta.Name, err)
				continue
			}
			fuz.mgr.updateTestStat(timeout, aHanged || vHanged)
			if timeout {
				// The victim program's timeout is most likely caused by attacker program because:
				// 1. Generator will not produce test pair that contains
				//    program exceeding timeout in profiling
				// 2. Double timeout as executor runs two test programs
				// 3. No memory trace overhead
				fuz.newResult(testP, nil, nil, nil,
					testP.A.Meta.TestIdx, testP.A.Meta.ClsIdx, testP.A.Meta.ClsMemIdx, testP.A.Meta.ClsMemProgIdx, testP.V.Meta.ClsMemProgIdx, testP.A.Meta.PredPC, testP.A.Meta.PredAddr, testP.V.Meta.PredPC, testP.V.Meta.PredAddr, testP.A.Meta.PredAddrLen, testP.V.Meta.PredAddrLen,
					testP.Interleave, testP.VPause, uint64(test.A.Opts.Flags), uint64(test.V.Opts.Flags), timeout, false, false, nil, nil, nil, nil, nil, nil, nil)
				fuz.mgr.updateTotResults()
				continue
			} else if aHanged || vHanged {
				// The victim program's timeout is most likely caused by attacker program because:
				// 1. Generator will not produce test pair that contains
				//    program exceeding hanged in profiling
				fuz.newResult(testP, nil, nil, nil,
					testP.A.Meta.TestIdx, testP.A.Meta.ClsIdx, testP.A.Meta.ClsMemIdx, testP.A.Meta.ClsMemProgIdx, testP.V.Meta.ClsMemProgIdx, testP.A.Meta.PredPC, testP.A.Meta.PredAddr, testP.V.Meta.PredPC, testP.V.Meta.PredAddr, testP.A.Meta.PredAddrLen, testP.V.Meta.PredAddrLen,
					testP.Interleave, testP.VPause, uint64(test.A.Opts.Flags), uint64(test.V.Opts.Flags), timeout, aHanged, vHanged, nil, nil, nil, nil, nil, nil, nil)
				fuz.mgr.updateTotResults()
				continue
			}

			vProgNum, err := strconv.Atoi(testP.V.Meta.Name)
			if err != nil {
				util.GFatalf("cannot convert program name %v to int: %v", testP.V.Meta.Name, err)
			}

			vEqual := true

			var aSCTrace, vSCTrace, aSCTraceExpect, vSCTraceExpect *trace.ProgSCTrace
			var vDiff []*trace.SCTraceDiff

			fuz.mgr.traceMu[vProgNum%fuz.mgr.traceMuNum].Lock()

			vTraceInfo, err := trace.LoadTraceInfoByProgName(fuz.mgr.cfg.TraceDir, testP.V.Meta.Name, false)
			if err != nil {
				util.GFatalf("worker %v load victim trace info: %v", fuz.index, err)
			}
			// some profiles doesn't contain syscall trace...
			// TODO: look into this
			if vTraceInfo.ScTraceName == "" {
				fuz.mgr.traceMu[vProgNum%fuz.mgr.traceMuNum].Unlock()
				log.Logf(0, "syscall trace for victim program %v does not exist, skip this test case", testP.V.Meta.Name)
				continue
			}
			vPreSCList, err := trace.LoadSCTrace(vTraceInfo, fuz.mgr.cfg.TraceDir)
			if err != nil {
				util.GFatalf("worker %v cannot load victim %v program syscall trace: %v", fuz.index, testP.V.Meta.Name, err)
			}
			vNoMatch := false
			vEqual, vSCTrace, vSCTraceExpect, vDiff, vNoMatch, err = SCStrCheck(vSCRaw, vPreSCList)
			if err != nil {
				util.GFatalf("worker %v cannot check %v program victim syscall trace: %v", fuz.index, testP.A.Meta.Name, err)
			}
			if vNoMatch {
				fuz.mgr.traceMu[vProgNum%fuz.mgr.traceMuNum].Unlock()
				log.Logf(0, "victim %v syscall trace no match, continue", testP.V.Meta.Name)
				continue
			}

			// Instrumentation: evaluate total results without non-determism identification
			if vEqual {
				if len(vPreSCList) > 1 {
					equal, _, _, _, _, _ := SCStrCheck(vSCRaw, vPreSCList[:1])
					if !equal {
						fuz.mgr.updateTotResults()
					}
				}
			} else {
				fuz.mgr.updateTotResults()
			}

			if !vEqual {
				var savedVSCRaw [][]string
				ms := uint32(0)
				if len(aCallInfo) == len(testP.A.P.Calls) && aCallInfo[len(aCallInfo)-1].Ms != 0 {
					ms = aCallInfo[len(aCallInfo)-1].Ms
				} else {
					ms = uint32(200000)
				}
				// When NDTestRounds is larger, non-determinism identification is better,
				// but test throughput is worse
				NDTestRounds := 3
				nextTest := false
				for i := 1; i <= NDTestRounds; i++ {
					savedVSCRaw, vEqual, vDiff, err = identifyNondet(fuz.mgr.progTarget, e, test, ms, vSCTraceExpect, vSCTrace, fuz.mgr.cfg.TestTimeout, i*5)
					if err != nil {
						fuz.mgr.traceMu[vProgNum%fuz.mgr.traceMuNum].Unlock()
						log.Logf(0, "identify non-determinism error: %v", err)
						nextTest = true
						break
					}
					if len(savedVSCRaw) != 0 {
						vPreSCList = append(vPreSCList, savedVSCRaw...)
						err = trace.SaveSCTrace(vTraceInfo, fuz.mgr.cfg.TraceDir, vPreSCList)
						if err != nil {
							util.GFatalf("worker %v cannot save new victim syscall trace: %v", fuz.index, err)
						}
					}
				}
				if nextTest {
					continue
				}
			}

			fuz.mgr.traceMu[vProgNum%fuz.mgr.traceMuNum].Unlock()

			if !vEqual {
				// miniAP, aMiniSCTrace := minimizeAttackProg(e, test, vSCTraceExpect, vDiff, fuz.mgr.cfg.TestTimeout)
				aCallDiag, vCallDiag := diagnose(e, test, vSCTraceExpect, vDiff, fuz.mgr.cfg.TestTimeout)
				aSCTrace, _ = trace.ParseSCTrace(aSCRaw)
				fuz.newResult(testP, nil, aCallDiag, vCallDiag,
					testP.A.Meta.TestIdx, testP.A.Meta.ClsIdx, testP.A.Meta.ClsMemIdx, testP.A.Meta.ClsMemProgIdx, testP.V.Meta.ClsMemProgIdx, testP.A.Meta.PredPC, testP.A.Meta.PredAddr, testP.V.Meta.PredPC, testP.V.Meta.PredAddr, testP.A.Meta.PredAddrLen, testP.V.Meta.PredAddrLen,
					testP.Interleave, testP.VPause, uint64(test.A.Opts.Flags), uint64(test.V.Opts.Flags), timeout, aHanged, vHanged, nil, vDiff, aSCTrace, nil, vSCTrace, aSCTraceExpect, vSCTraceExpect)
			}

		}
	}
	atomic.AddUint64(&fuz.mgr.stat.StatExecCnt, 0xffffffffffffffff)
	log.Logf(0, "worker %v finished", fuz.index)
	fuz.wg.Done()
}

func (mgr *Manager) runFuzzer(debug bool) {
	var numfuzzer int
	var w *Worker

	numfuzzer = mgr.vmpool.Count()
	wg := &sync.WaitGroup{}
	mgr.workerWg = wg
	for i := 0; i < numfuzzer; i++ {
		w = &Worker{
			mgr:   mgr,
			index: i,
			wg:    wg,
		}
		wg.Add(1)
		go w.run(debug)
	}
}

func (mgr *Manager) loop() {
	start := time.Now()
	workerDone := make(chan struct{}, 1)
	if !mgr.cfg.Server {
		go func() {
			mgr.workerWg.Wait()
			close(workerDone)
		}()
	}
	for {
		select {
		case <-vm.Shutdown:
			// TODO: wait all fuzzers terminate gracefully, e.g shutdown VMs
			log.Logf(0, "manager shutting down...")
			return
		case <-time.After(mgr.cfg.PrintInterval):
			stat := mgr.stat.SafeLoad()
			duration := time.Since(start)
			throughput := float64(stat.StatTest) / duration.Seconds()
			s := fmt.Sprintf("exec=%v, test=%v, timeout=%v, hanged=%v, duration=%v, result=%v, totResult=%v, throughput=%.2f(test/s)",
				stat.StatExecCnt,
				stat.StatTest,
				stat.StatTimeout,
				stat.StatHanged,
				duration.Round(time.Second).String(),
				stat.StatResult,
				stat.StatTotRes,
				throughput,
			)
			if mgr.pairGen != nil {
				s += ", [generator]: " + mgr.pairGen.Log()
			}
			if mgr.cfg.Server {
				s += ", [clients]: "
				mgr.clientInfoMu.Lock()
				for _, info := range mgr.clientInfo {
					if time.Since(info.TimeStamp) > 2*ClientHeartbeatInterval {
						s += fmt.Sprintf("%v: lost, ", info.Name)
					} else {
						s += fmt.Sprintf("%v: online, ", info.Name)
					}
				}
				mgr.clientInfoMu.Unlock()
			}
			log.Logf(0, "%v", s)
		case <-workerDone:
			log.Logf(0, "worker finished all jobs, manager shutting down...")
			return
		}

	}
}

func main() {
	var mgr Manager

	log.Logf(0, "starting namespace test manager...")
	flag.Parse()
	mgr.initConfig(*flagConfig)
	mgr.initClient()
	mgr.initVMPool(*flagDebug)
	mgr.initMisc()
	mgr.initServer()
	osutil.HandleInterrupts(vm.Shutdown)
	mgr.runFuzzer(*flagDebug)

	mgr.loop()
}
