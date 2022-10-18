package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"path"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/prog"
	"github.com/rss/kit/pgen"
	"github.com/rss/kit/result"
	"github.com/rss/kit/util"
)

const ClientHeartbeatInterval time.Duration = 10 * time.Second

type ManagerServer interface {
	GetVMImage(int, *RPCVMImage) error
	GetProgNamePair(int, *RPCProgNamePairBatch) error
	NewTestResult(*result.TestResult, *int) error
	NewClientInfo(*RPCClientInfo, *int) error
}

type ManagerCallClient struct {
	mu     *sync.Mutex // RPCClient's `call` is not atomic
	client *rpctype.RPCClient
}

type ManagerClient struct {
	progPairClient   *ManagerCallClient
	resultClient     *ManagerCallClient
	clientInfoClient *ManagerCallClient
}

type RPCVMImage struct {
	Image []byte
	Key   []byte
}

type RPCProgNamePair struct {
	AMeta      pgen.ProgMeta
	VMeta      pgen.ProgMeta
	Interleave bool
	VPause     uint8
}

type RPCProgNamePairBatch struct {
	Pairs []RPCProgNamePair
}

type RPCClientInfo struct {
	Name      string
	TimeStamp time.Time
	Stat      *ManagerStat
}

func (mgr *Manager) GetVMImage(p int, s *RPCVMImage) error {
	var err error
	log.Printf("reading image and key file...")
	s.Image, err = ioutil.ReadFile(mgr.vmenv.Image)
	if err != nil {
		return fmt.Errorf("cannot open snapshot image: %v", err)
	}
	s.Key, err = ioutil.ReadFile(mgr.vmenv.SSHKey)
	if err != nil {
		return fmt.Errorf("cannot open snapshot image: %v", err)
	}
	log.Printf("reading image and key file done!")
	return nil
}

func (mgr *Manager) GetProgNamePair(n int, pb *RPCProgNamePairBatch) error {
	if n <= 0 {
		return fmt.Errorf("n should be greater than 0")
	}
	for n >= 0 {
		p, ok := <-mgr.pairCh
		if !ok {
			break
		}
		pb.Pairs = append(pb.Pairs,
			RPCProgNamePair{
				AMeta:      *p.A.Meta,
				VMeta:      *p.V.Meta,
				Interleave: p.Interleave,
				VPause:     p.VPause,
			})
		n--
	}
	return nil
}

func (mgr *Manager) NewTestResult(r *result.TestResult, p *int) error {
	err := result.SerializeTestResult(mgr.resultTmpDir, r)
	if err != nil {
		return fmt.Errorf("cannot serialize new test results: %v", err)
	}
	return nil

}

func (mgr *Manager) NewClientInfo(c *RPCClientInfo, p *int) error {
	mgr.clientInfoMu.Lock()
	defer mgr.clientInfoMu.Unlock()
	mgr.clientInfo[c.Name] = c
	return nil
}

func NewManagerServer(addr string, mgr ManagerServer) (*rpctype.RPCServer, error) {
	return rpctype.NewRPCServer(addr, "Server", mgr)
}

func (c *ManagerCallClient) GetVMImage() ([]byte, []byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var rpcReply RPCVMImage
	err := c.client.Call("Server.GetVMImage", 0, &rpcReply)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot start GetVMImage rpc: %v", err)
	}

	return rpcReply.Image, rpcReply.Key, nil
}

func (c *ManagerCallClient) GetProgNamePair(n int) ([]RPCProgNamePair, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var rpcReply RPCProgNamePairBatch
	err := c.client.Call("Server.GetProgNamePair", n, &rpcReply)
	if err != nil {
		return nil, fmt.Errorf("cannot start GetProgNamePair rpc: %v", err)
	}
	return rpcReply.Pairs, nil
}

func (c *ManagerCallClient) NewTestResult(r *result.TestResult) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	err := c.client.Call("Server.NewTestResult", r, nil)
	if err != nil {
		return fmt.Errorf("cannot start NewTestResult rpc: %v", err)
	}
	return nil
}

func (c *ManagerCallClient) NewClientInfo(name string, stat *ManagerStat) error {
	ci := &RPCClientInfo{
		Name:      name,
		Stat:      stat,
		TimeStamp: time.Now(),
	}
	err := c.client.Call("Server.NewClientInfo", ci, nil)
	if err != nil {
		return fmt.Errorf("cannot start NewClientInfo rpc: %v", err)
	}
	return nil
}

func NewManagerCallClient(addr string, timeScale time.Duration) (*ManagerCallClient, error) {
	var err error
	c := &ManagerCallClient{mu: &sync.Mutex{}}
	c.client, err = rpctype.NewRPCClient(addr, timeScale)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func NewManagerClient(addr string, timeScale time.Duration) (*ManagerClient, error) {
	var err error
	c := &ManagerClient{}
	c.progPairClient, err = NewManagerCallClient(addr, timeScale)
	if err != nil {
		return nil, err
	}
	c.resultClient, err = NewManagerCallClient(addr, timeScale)
	if err != nil {
		return nil, err
	}
	c.clientInfoClient, err = NewManagerCallClient(addr, timeScale)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (c *ManagerClient) NewTestResult(r *result.TestResult) error {
	return c.resultClient.NewTestResult(r)
}

func (c *ManagerClient) GetProgNamePair(n int) ([]RPCProgNamePair, error) {
	return c.progPairClient.GetProgNamePair(n)
}

func (c *ManagerClient) GetVMImage() ([]byte, []byte, error) {
	// just use progPair client, this call is only invoked once
	return c.progPairClient.GetVMImage()
}

func (c *ManagerClient) NewClientInfo(name string, stat *ManagerStat) error {
	return c.clientInfoClient.NewClientInfo(name, stat)
}

type ClientTestGenerator struct {
	target        *prog.Target
	progDir       string
	c             *ManagerClient
	namePairCache []RPCProgNamePair
	downloadBatch int
	statPair      uint64
}

func InitClientTestGenerator(target *prog.Target, progDir string, c *ManagerClient, downloadBatch int) *ClientTestGenerator {
	return &ClientTestGenerator{
		target:        target,
		progDir:       progDir,
		c:             c,
		downloadBatch: downloadBatch,
	}
}

func (gen *ClientTestGenerator) Generate() (*pgen.ProgPair, error) {
	var err error
	if len(gen.namePairCache) == 0 {
		gen.namePairCache, err = gen.c.GetProgNamePair(gen.downloadBatch)
		if err != nil {
			return nil, fmt.Errorf("cannot download program pairs: %v", err)
		}
		if len(gen.namePairCache) == 0 {
			return nil, nil
		}
	}
	namePair := gen.namePairCache[0]
	gen.namePairCache = gen.namePairCache[1:]
	apPath := path.Join(gen.progDir, namePair.AMeta.Name)
	ap, err := util.ReadProg(apPath, gen.target, prog.NonStrict)
	if err != nil {
		return nil, fmt.Errorf("cannot read attack program: %v", err)
	}
	vpPath := path.Join(gen.progDir, namePair.VMeta.Name)
	vp, err := util.ReadProg(vpPath, gen.target, prog.NonStrict)
	if err != nil {
		return nil, fmt.Errorf("cannot read victim program: %v", err)
	}
	atomic.AddUint64(&gen.statPair, 1)
	return &pgen.ProgPair{
		A: &pgen.ProgGen{
			P:    ap,
			Meta: &namePair.AMeta,
		},
		V: &pgen.ProgGen{
			P:    vp,
			Meta: &namePair.VMeta,
		},
		Interleave: namePair.Interleave,
		VPause:     namePair.VPause,
	}, nil
}

func (gen *ClientTestGenerator) Log() string {
	nPair := atomic.LoadUint64(&gen.statPair)
	return fmt.Sprintf("statPair = %v", nPair)
}
