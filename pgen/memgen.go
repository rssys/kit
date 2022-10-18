package pgen

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"sync"

	"github.com/google/syzkaller/prog"
)

type MemTestInfo struct {
	Idx       int    `json:"idx"`
	CallStack uint64 `json:"call_stack"`
	PC        uint64 `json:"pc,omitempty"`
	Progs     []int  `json:"progs"`
	Addr      uint64 `json:"addr"`
	Width     uint8  `json:"width"`
	Read      bool   `json:"read"`
}

type MemPair struct {
	WMemIdx int     `json:"w_mem_idx"`
	RMemIdx int     `json:"r_mem_idx"`
	Score   float64 `json:"score"`
}

type ClsTest struct {
	Tests []MemPair `json:"tests"`
	Score float64   `json:"score"`
}

type TestPred struct {
	Mem   []*MemTestInfo `json:"mem"`
	Cls   []ClsTest      `json:"cls"`
	Score float64        `json:"score"`
}

const (
	NoInterleave int = iota
	Interleaving
)

type ClsTestGenerator struct {
	gen      *TestGenerator
	mem      []*MemTestInfo
	tests    []MemPair
	progDir  string
	target   *prog.Target
	testIdx  int
	aProgIdx int
	vProgIdx int
	score    float64
}

type TestGenerator struct {
	clsIdx   int
	gens     []*ClsTestGenerator
	nextGens []*ClsTestGenerator
	mu       sync.Mutex
	done     map[int]map[int]bool // global map of done pairs
	statTest int                  // number of tests (include interleave) generated
}

func (gen *TestGenerator) Generate() (*ProgPair, error) {
	for {
		if len(gen.gens) == 0 {
			return nil, nil
		}
		if gen.clsIdx == len(gen.gens) {
			gen.mu.Lock()
			gen.gens = gen.nextGens
			gen.nextGens = []*ClsTestGenerator{}
			gen.clsIdx = 0
			gen.mu.Unlock()
			continue
		}
		curGen := gen.gens[gen.clsIdx]
		pair, err := curGen.Generate()
		if pair == nil && err == nil {
			gen.mu.Lock()
			gen.clsIdx++
			gen.mu.Unlock()
			continue
		}
		pair.A.Meta.ClsIdx = gen.clsIdx
		pair.V.Meta.ClsIdx = gen.clsIdx
		gen.mu.Lock()
		gen.nextGens = append(gen.nextGens, curGen)
		gen.clsIdx++
		gen.mu.Unlock()
		return pair, err
	}
}

func (gen *TestGenerator) Log() string {
	gen.mu.Lock()
	defer gen.mu.Unlock()
	if len(gen.gens) == 0 {
		return "empty"
	}
	i := gen.clsIdx
	if i == len(gen.gens) {
		i--
	}
	s := fmt.Sprintf("statTest=%v, numCls=%v, clsIdx=%v, clsScore=%v, ",
		gen.statTest, len(gen.gens), i, gen.gens[i].score)
	c := gen.gens[i]
	return s + c.Log()
}

func (gen *ClsTestGenerator) Generate() (*ProgPair, error) {
	for {
		var pair *ProgPair
		if gen.testIdx == len(gen.tests) {
			return nil, nil
		}
		test := gen.tests[gen.testIdx]
		if gen.aProgIdx == len(gen.mem[test.WMemIdx].Progs) {
			gen.testIdx++
			gen.aProgIdx = 0
			gen.vProgIdx = 0
			continue
		}
		if gen.vProgIdx == len(gen.mem[test.RMemIdx].Progs) {
			gen.aProgIdx++
			gen.vProgIdx = 0
			continue
		}
		a := gen.mem[test.WMemIdx].Progs[gen.aProgIdx]
		v := gen.mem[test.RMemIdx].Progs[gen.vProgIdx]
		if _, ok := gen.gen.done[a]; ok {
			if gen.gen.done[a][v] {
				gen.vProgIdx++
				continue
			}
		}
		aName := strconv.FormatInt(int64(a), 10)
		aPath := path.Join(gen.progDir, aName)
		aProgBytes, err := ioutil.ReadFile(aPath)
		if err != nil {
			return nil, err
		}
		pair = &ProgPair{
			A:          &ProgGen{},
			V:          &ProgGen{},
			Interleave: false,
			VPause:     0,
		}
		pair.A.P, err = gen.target.Deserialize(aProgBytes, prog.NonStrict)
		if err != nil {
			gen.aProgIdx++
			gen.vProgIdx = 0
			continue
		}
		pair.A.Meta = &ProgMeta{
			Name:          aName,
			TestIdx:       gen.gen.statTest,
			ClsMemIdx:     gen.testIdx,
			ClsMemProgIdx: gen.aProgIdx,
			PredPC:        gen.mem[test.WMemIdx].PC,
			PredAddr:      gen.mem[test.WMemIdx].Addr,
			PredAddrLen:   1 << gen.mem[test.WMemIdx].Width,
		}

		vName := strconv.FormatInt(int64(v), 10)
		vPath := path.Join(gen.progDir, vName)
		vProgBytes, err := ioutil.ReadFile(vPath)
		if err != nil {
			return nil, err
		}
		pair.V.P, err = gen.target.Deserialize(vProgBytes, prog.NonStrict)
		if err != nil {
			gen.vProgIdx++
			continue
		}
		pair.V.Meta = &ProgMeta{
			Name:          vName,
			TestIdx:       gen.gen.statTest,
			ClsMemIdx:     gen.testIdx,
			ClsMemProgIdx: gen.vProgIdx,
			PredPC:        gen.mem[test.RMemIdx].PC,
			PredAddr:      gen.mem[test.RMemIdx].Addr,
			PredAddrLen:   1 << gen.mem[test.RMemIdx].Width,
		}

		if _, ok := gen.gen.done[a]; !ok {
			gen.gen.done[a] = map[int]bool{}
		}
		gen.gen.done[a][v] = true
		gen.vProgIdx++
		gen.gen.statTest++
		return pair, nil
	}
}

func InitTestGenerator(target *prog.Target, progDir string, predPath string) (*TestGenerator, error) {
	gen := &TestGenerator{
		clsIdx: 0,
		done:   map[int]map[int]bool{},
	}

	f, err := os.Open(predPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open prediction file: %v", err)
	}
	dec := json.NewDecoder(f)
	pred := &TestPred{}
	err = dec.Decode(pred)
	if err != nil {
		return nil, fmt.Errorf("cannot decode prediction file: %v", err)
	}
	for _, rgTest := range pred.Cls {
		rgen := &ClsTestGenerator{
			gen:      gen,
			target:   target,
			progDir:  progDir,
			testIdx:  0,
			aProgIdx: 0,
			vProgIdx: 0,
			tests:    rgTest.Tests,
			mem:      pred.Mem,
			score:    rgTest.Score,
		}
		gen.gens = append(gen.gens, rgen)
	}

	return gen, nil
}

func (gen *ClsTestGenerator) Log() string {
	if len(gen.tests) == 0 {
		return "empty tests..."
	}
	if gen.testIdx == len(gen.tests) {
		return "done"
	}
	test := gen.tests[gen.testIdx]
	return fmt.Sprintf("testIdx=%v, testScore=%.6f",
		gen.testIdx, test.Score)
}
