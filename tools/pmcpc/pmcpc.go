package main

import (
	"crypto/sha1"
	"flag"
	"io/ioutil"
	"log"
	"path"
	"runtime"
	"sort"
	"strconv"
	"sync"

	"github.com/google/syzkaller/prog"
	"github.com/rss/kit/exec"
	"github.com/rss/kit/ns"
	"github.com/rss/kit/pgen"
	"github.com/rss/kit/trace"
	"github.com/rss/kit/util"
)

var (
	flagGenMemtraceMap     = flag.Bool("gen_memtrace_map", false, "generate memory trace map")
	flagProgDir            = flag.String("prog_dir", "", "trace direcotry")
	flagTraceDir           = flag.String("trace_dir", "", "trace direcotry")
	flagThread             = flag.Int("thread", 1, "number of threads for generating memory trace map")
	flagMemtraceMap        = flag.String("memtrace_map", "", "memory trace map path")
	flagGenNonePred        = flag.Bool("gen_none_pred", false, "generate prediction without cluster")
	flagGenPCPred          = flag.Bool("gen_pc_pred", false, "generate (w_pc, r_pc) cluster prediction")
	flagGenPCAddrPred      = flag.Bool("gen_pc_addr_pred", false, "generate (w_pc, w_addr, r_pc, r_addr) cluster prediction")
	flagGenPCCallStackPred = flag.Bool("gen_pc_call_stack_pred", false, "generate (w_call_stack, w_pc, r_call_stack, r_pc) cluster prediction")
	flagPred               = flag.String("pred", "", "prediction path")
	flagMaxCallStack       = flag.Int("max_call_stack", 0, "maximum call stack depth")
	flagMaxProg            = flag.Int("max_prog", 5, "maximum number of programs for r/w side of memory pair; lower value saves memory, but introduces randomness (default 5)")
)

type MemInfo struct {
	Progs map[uint64]map[uint64]map[int]bool
}

type MemHeatMap struct {
	Mem [2][4]map[uint64]*MemInfo
}

func read2Index(read bool) int {
	if read {
		return 1
	} else {
		return 0
	}
}

func index2Read(index int) bool {
	if index == 0 {
		return false
	} else {
		return true
	}
}

func len2wid(len uint32) int {
	ret := -1
	switch len {
	case 1:
		ret = 0
	case 2:
		ret = 1
	case 4:
		ret = 2
	case 8:
		ret = 3
	}
	return ret
}

func removeOverlapMemoryTrace(t []*exec.MemTrace) []*exec.MemTrace {
	memWrMap := make(map[uint64][]int)
	truncateFlag := []bool{}
	truncated := []*exec.MemTrace{}

	for i, m := range t {
		block := m.Addr & 0xfffffffffffffff8
		shift := uint32(m.Addr & 0x7)

		if m.Type == exec.MemtraceRead {
			// truncate read access when memory region is written by
			// previous memory access
			written := true
			if bytesMap, ok := memWrMap[block]; ok {
				for k := shift; k < shift+m.Len; k++ {
					if bytesMap[k] == -1 {
						written = false
						break
					}
				}
			} else {
				written = false
			}
			truncateFlag = append(truncateFlag, written)
		} else if m.Type == exec.MemtraceWrite {
			// update memory write map
			// truncate all write memory access for now, correct later
			if _, ok := memWrMap[block]; !ok {
				memWrMap[block] =
					[]int{-1, -1, -1, -1, -1, -1, -1, -1}
			}
			for k := shift; k < shift+m.Len; k++ {
				memWrMap[block][k] = i
			}
			truncateFlag = append(truncateFlag, true)
		} else {
			truncateFlag = append(truncateFlag, false)
		}
	}

	// calculate write memory access truncation
	for _, memWrMap8 := range memWrMap {
		for _, wrTraceIdx := range memWrMap8 {
			if wrTraceIdx != -1 {
				truncateFlag[wrTraceIdx] = false
			}
		}
	}

	for i, truncate := range truncateFlag {
		if !truncate {
			truncated = append(truncated, t[i])
		}
	}

	return truncated
}

func alignMemoryTrace(t []*exec.MemTrace) []*exec.MemTrace {
	aligned := []*exec.MemTrace{}
	for _, m := range t {
		if m.Type != exec.MemtraceRead && m.Type != exec.MemtraceWrite {
			aligned = append(aligned, m)
			continue
		}
		total := uint32(m.Len)
		addr := m.Addr
		for total > 0 {
			lowestOne := (addr & (addr - 1)) ^ addr
			newLen := uint32(lowestOne & 0x7)
			if newLen == 0 {
				newLen = 8
			}
			for newLen > total {
				newLen >>= 1
			}
			mt := &exec.MemTrace{
				PC:   m.PC,
				Addr: addr,
				Len:  newLen,
				Type: m.Type,
			}
			aligned = append(aligned, mt)
			total -= newLen
			addr += uint64(newLen)
		}
	}
	return aligned
}

var printEvery int = 50

type memRegion struct {
	addr  uint64
	width int
}

func memOverlap(r memRegion) []memRegion {
	overlaps := []memRegion{}
	for w := r.width; w < 4; w++ {
		overlaps = append(overlaps, memRegion{
			addr:  r.addr & (0xffffffffffffffff << w),
			width: w,
		})
	}
	for w := 0; w < r.width; w++ {
		for a := r.addr; a < r.addr+(1<<r.width); a += 1 << w {
			overlaps = append(overlaps, memRegion{
				addr:  a,
				width: w,
			})
		}
	}
	return overlaps
}

type Hash2Uint64 struct {
	m       map[string]uint64
	hashCnt uint64
}

func (h *Hash2Uint64) Uint64(str string) uint64 {
	var u uint64
	u, ok := h.m[str]
	if !ok {
		u = h.hashCnt
		h.m[str] = h.hashCnt
		h.hashCnt++
	}
	return u
}

type CallStack struct {
	savedCallSites []uint64
	savedCallID    []uint64
	cachedHash     uint64
	maxSize        int
	callSitesDepth int
	hash2uint64    *Hash2Uint64
}

func (cs *CallStack) SetMaxSize(maxSize int) {
	cs.maxSize = maxSize
}

func (cs *CallStack) Call(callsite, callid uint64) {
	if len(cs.savedCallSites) < cs.maxSize {
		cs.savedCallSites = append(cs.savedCallSites, callsite)
		cs.savedCallID = append(cs.savedCallID, callid)
		cs.cachedHash = 0xffffffffffffffff
	}
	cs.callSitesDepth++
}

func (cs *CallStack) Return(pc, callid uint64) {
	l := len(cs.savedCallSites)
	if l == 0 {
		log.Printf("return on empty call stack")
		return
	}
	if cs.callSitesDepth <= cs.maxSize {
		if callid != cs.savedCallID[l-1] {
			log.Printf("ret (pc = 0x%x, id = 0x%x) not match call (pc = 0x%x, id = 0x%x)", pc, callid, cs.savedCallSites[l-1], cs.savedCallID[l-1])
			i := l - 1
			log.Printf("------Print Call Stack-----")
			for i >= 0 && (l-1-i) <= 5 {
				log.Printf("call (pc = 0x%x, id = 0x%x)", cs.savedCallSites[i], cs.savedCallID[i])
				i--
			}

		}
		cs.savedCallSites = cs.savedCallSites[:l-1]
		cs.savedCallID = cs.savedCallID[:l-1]
		cs.cachedHash = 0xffffffffffffffff
	}
	cs.callSitesDepth--
}

func (cs *CallStack) Hash() uint64 {
	if cs.cachedHash == 0xffffffffffffffff {
		b := []byte{}
		for _, callsite := range cs.savedCallSites {
			for i := 0; i < 8; i++ {
				b = append(b, byte(callsite))
				callsite >>= 8
			}
		}
		s := sha1.New()
		str := string(s.Sum(b))
		cs.cachedHash = cs.hash2uint64.Uint64(str)
	}
	return cs.cachedHash
}

// Use raw trace instead of truncated trace. So we can only calculate counter after
// generating the complete resource memory regions.
func rsMemHeatmapWorker(th int, wg *sync.WaitGroup, heatMap *MemHeatMap, memMu *sync.Mutex, target *prog.Target, rsTable ns.ResourceInfoTable, fdCallTb ns.FdDefCallTable, nonFdCallTb ns.NonFdCallTable, traceDir, progDir string, traceNames []string, hash2uint64 *Hash2Uint64) {
	defer wg.Done()
	for i, name := range traceNames {
		traceInfo, err := trace.LoadTraceInfoByTraceName(traceDir, name)
		if err != nil {
			log.Fatalf("cannot load trace: %v", err)
		}
		raw, err := trace.LoadMemtrace(traceInfo, traceDir)
		if err != nil {
			log.Fatalf("cannot load trace: %v", err)
		}
		progBytes, err := ioutil.ReadFile(path.Join(progDir, traceInfo.Name))
		if err != nil {
			log.Fatalf("cannot read prog: %v", err)
		}
		p, err := target.Deserialize(progBytes, prog.NonStrict)
		if err != nil {
			log.Printf("cannot deserialize prog: %v", err)
			continue
		}
		progNum, err := strconv.Atoi(traceInfo.Name)
		if err != nil {
			log.Fatalf("cannot convert program name %v to integer: %v", traceInfo.Name, err)
		}

		a := ns.ResourceCallAnalysis(p)
		memMu.Lock()
		for call, callMemTrace := range raw {
			if !traceInfo.Attack {
				if _, rsCall := a[call]; !rsCall {
					continue
				}

			}
			// align memory trace
			callAlignMemTrace := alignMemoryTrace(callMemTrace)

			// remove inner-call overlap memory trace
			callNoOverlapMemtrace := removeOverlapMemoryTrace(callAlignMemTrace)

			// call stack
			cs := &CallStack{hash2uint64: hash2uint64}
			cs.SetMaxSize(*flagMaxCallStack)

			// use call ID as the initial callsite
			// cs.Call((uint64)(p.Calls[call].Meta.ID), 0xffffffffffffffff)

			for _, t := range callNoOverlapMemtrace {

				if t.Type == exec.MemtraceCall {
					cs.Call(t.PC, t.Addr)
				} else if t.Type == exec.MemtraceRet {
					cs.Return(t.PC, t.Addr)
				}

				// only considers attack-write and victim-read
				rw := -1
				if (t.Type == exec.MemtraceWrite && traceInfo.Attack) || (t.Type == exec.MemtraceRead && !traceInfo.Attack) {
					rw = read2Index(t.Type == exec.MemtraceRead)
				} else {
					continue
				}

				// updates program array and total memory access count
				memInfo, ok := heatMap.Mem[rw][len2wid(t.Len)][t.Addr]
				if !ok {
					memInfo = &MemInfo{
						Progs: map[uint64]map[uint64]map[int]bool{},
					}
					heatMap.Mem[rw][len2wid(t.Len)][t.Addr] = memInfo
				}

				// For victim program,
				// it must contains resource call to be tested
				add := false
				if !traceInfo.Attack {
					if _, rsCall := a[call]; rsCall {
						add = true
					}
				} else {
					add = true
				}

				if add {
					callstack := cs.Hash()
					if _, ok := memInfo.Progs[t.PC]; !ok {
						memInfo.Progs[t.PC] = map[uint64]map[int]bool{}
					}
					if _, ok := memInfo.Progs[t.PC][callstack]; !ok {
						memInfo.Progs[t.PC][callstack] = map[int]bool{}
					}
					memInfo.Progs[t.PC][callstack][progNum] = true
				}

			}
		}
		memMu.Unlock()
		if i%printEvery == 0 {
			log.Printf("[heatmap] thread %v, processed %%%.2f(%v/%v) traces...", th, 100.0*float32(i)/float32(len(traceNames)), i, len(traceNames))
		}
	}
}

func rsMemHeatmap(threads int, target *prog.Target, rsTable ns.ResourceInfoTable, fdCallTb ns.FdDefCallTable, nonFdCallTb ns.NonFdCallTable, traceDir, progDir string) *MemHeatMap {
	traceNames, err := trace.AllTraceInfoNames(traceDir)
	if err != nil {
		log.Fatalf("cannot get trace names: %v", err)
	}
	if threads > len(traceNames) {
		threads = len(traceNames)
	}
	heatMap := &MemHeatMap{
		Mem: [2][4]map[uint64]*MemInfo{{{}, {}, {}, {}}, {{}, {}, {}, {}}},
	}
	hash2Uint64 := &Hash2Uint64{m: map[string]uint64{}}
	mu := &sync.Mutex{}
	wg := &sync.WaitGroup{}
	assigned := 0
	trunkSize := len(traceNames) / threads
	for th := 0; th < threads; th++ {
		if th == threads-1 {
			trunkSize = len(traceNames) - assigned
		}
		wg.Add(1)
		go rsMemHeatmapWorker(th, wg, heatMap, mu, target, rsTable, fdCallTb, nonFdCallTb, traceDir, progDir, traceNames[assigned:assigned+trunkSize], hash2Uint64)
		assigned += trunkSize
	}
	wg.Wait()
	return heatMap
}

func genMemTestInfoNew(idx int, addr, pc uint64, callstack uint64, width uint8, read bool, progMap map[int]bool) *pgen.MemTestInfo {
	progs := []int{}
	pMax := *flagMaxProg
	pCnt := 0
	for p := range progMap {
		progs = append(progs, p)
		pCnt++
		if pCnt > pMax {
			break
		}
	}
	return &pgen.MemTestInfo{
		Addr:      addr,
		PC:        pc,
		CallStack: callstack,
		Width:     width,
		Read:      read,
		Progs:     progs,
		Idx:       idx,
	}
}

func genPCCallStackCluster(heatMap *MemHeatMap) *pgen.TestPred {
	gen := &pgen.TestPred{
		Mem: []*pgen.MemTestInfo{},
		Cls: []pgen.ClsTest{},
	}
	memTestInfoMap := [2][4]map[uint64][]int{{{}, {}, {}, {}}, {{}, {}, {}, {}}}
	clsMap := map[uint64]map[uint64]map[uint64]map[uint64]*pgen.ClsTest{}
	for rw, _mem := range heatMap.Mem {
		for w, __mem := range _mem {
			for a, info := range __mem {
				for pc, csMap := range info.Progs {
					for cs, progs := range csMap {
						ti := genMemTestInfoNew(len(gen.Mem), a, pc, cs, uint8(w), index2Read(rw), progs)
						if _, ok := memTestInfoMap[rw][w][a]; !ok {
							memTestInfoMap[rw][w][a] = []int{}
						}
						memTestInfoMap[rw][w][a] = append(memTestInfoMap[rw][w][a], len(gen.Mem))
						gen.Mem = append(gen.Mem, ti)
					}
				}
			}
		}
	}
	for i, m := range gen.Mem {
		for _, ol := range memOverlap(memRegion{addr: m.Addr, width: int(m.Width)}) {
			for _, oIdx := range memTestInfoMap[read2Index(!m.Read)][ol.width][ol.addr] {
				if oIdx < i {
					// already covered
					continue
				}
				wMemIdx := i
				rMemIdx := oIdx
				if m.Read {
					wMemIdx, rMemIdx = rMemIdx, wMemIdx
				}
				wpc := gen.Mem[wMemIdx].PC
				wcs := gen.Mem[wMemIdx].CallStack
				rpc := gen.Mem[rMemIdx].PC
				rcs := gen.Mem[rMemIdx].CallStack
				if _, ok := clsMap[wcs]; !ok {
					clsMap[wcs] = map[uint64]map[uint64]map[uint64]*pgen.ClsTest{}
				}
				if _, ok := clsMap[wcs][wpc]; !ok {
					clsMap[wcs][wpc] = map[uint64]map[uint64]*pgen.ClsTest{}
				}
				if _, ok := clsMap[wcs][wpc][rcs]; !ok {
					clsMap[wcs][wpc][rcs] = map[uint64]*pgen.ClsTest{}
				}
				if _, ok := clsMap[wcs][wpc][rcs][rpc]; !ok {
					clsMap[wcs][wpc][rcs][rpc] = &pgen.ClsTest{Score: 0.0}
				}
				nTests := float64(len(gen.Mem[wMemIdx].Progs)) * float64(len(gen.Mem[rMemIdx].Progs))
				clsMap[wcs][wpc][rcs][rpc].Score += nTests
				clsMap[wcs][wpc][rcs][rpc].Tests = append(clsMap[wcs][wpc][rcs][rpc].Tests, pgen.MemPair{WMemIdx: wMemIdx, RMemIdx: rMemIdx, Score: nTests})
			}
		}
	}
	for _, wpcMap := range clsMap {
		for _, rcsMap := range wpcMap {
			for _, rpcMap := range rcsMap {
				for _, cls := range rpcMap {
					gen.Cls = append(gen.Cls, *cls)
				}
			}
		}
	}
	sort.Slice(gen.Cls, func(i, j int) bool {
		return gen.Cls[i].Score < gen.Cls[j].Score
	})
	for _, cls := range gen.Cls {
		sort.Slice(cls.Tests, func(i, j int) bool {
			return cls.Tests[i].Score < cls.Tests[j].Score
		})
	}
	return gen

}

func genPCCluster(heatMap *MemHeatMap) *pgen.TestPred {
	gen := &pgen.TestPred{
		Mem: []*pgen.MemTestInfo{},
		Cls: []pgen.ClsTest{},
	}
	memTestInfoMap := [2][4]map[uint64][]int{{{}, {}, {}, {}}, {{}, {}, {}, {}}}
	clsMap := map[uint64]map[uint64]*pgen.ClsTest{}
	for rw, _mem := range heatMap.Mem {
		for w, __mem := range _mem {
			for a, info := range __mem {
				for pc, csMap := range info.Progs {
					progs := map[int]bool{}
					for _, csProgs := range csMap {
						for p := range csProgs {
							progs[p] = true
						}
					}
					ti := genMemTestInfoNew(len(gen.Mem), a, pc, 0, uint8(w), index2Read(rw), progs)
					if _, ok := memTestInfoMap[rw][w][a]; !ok {
						memTestInfoMap[rw][w][a] = []int{}
					}
					memTestInfoMap[rw][w][a] = append(memTestInfoMap[rw][w][a], len(gen.Mem))
					gen.Mem = append(gen.Mem, ti)
				}
			}
		}
	}
	for i, m := range gen.Mem {
		for _, ol := range memOverlap(memRegion{addr: m.Addr, width: int(m.Width)}) {
			for _, oIdx := range memTestInfoMap[read2Index(!m.Read)][ol.width][ol.addr] {
				if oIdx < i {
					// already covered
					continue
				}
				wMemIdx := i
				rMemIdx := oIdx
				if m.Read {
					wMemIdx, rMemIdx = rMemIdx, wMemIdx
				}
				wpc := gen.Mem[wMemIdx].PC
				rpc := gen.Mem[rMemIdx].PC
				if _, ok := clsMap[wpc]; !ok {
					clsMap[wpc] = map[uint64]*pgen.ClsTest{}
				}
				if _, ok := clsMap[wpc][rpc]; !ok {
					clsMap[wpc][rpc] = &pgen.ClsTest{Score: 0.0}
				}
				nTests := float64(len(gen.Mem[wMemIdx].Progs)) * float64(len(gen.Mem[rMemIdx].Progs))
				clsMap[wpc][rpc].Score += nTests
				clsMap[wpc][rpc].Tests = append(clsMap[wpc][rpc].Tests, pgen.MemPair{WMemIdx: wMemIdx, RMemIdx: rMemIdx, Score: nTests})
			}
		}
	}
	for _, rpcMap := range clsMap {
		for _, cls := range rpcMap {
			gen.Cls = append(gen.Cls, *cls)
		}
	}
	sort.Slice(gen.Cls, func(i, j int) bool {
		return gen.Cls[i].Score < gen.Cls[j].Score
	})
	for _, cls := range gen.Cls {
		sort.Slice(cls.Tests, func(i, j int) bool {
			return cls.Tests[i].Score < cls.Tests[j].Score
		})
	}
	return gen

}

func genNoneCluster(heatMap *MemHeatMap) *pgen.TestPred {
	gen := &pgen.TestPred{
		Mem: []*pgen.MemTestInfo{},
		Cls: []pgen.ClsTest{},
	}
	memTestInfoMap := [2][4]map[uint64][]int{{{}, {}, {}, {}}, {{}, {}, {}, {}}}
	for rw, _mem := range heatMap.Mem {
		for w, __mem := range _mem {
			for a, info := range __mem {
				progs := map[int]bool{}
				for _, csMap := range info.Progs {
					for _, csProgs := range csMap {
						for p := range csProgs {
							progs[p] = true
						}
					}
				}
				ti := genMemTestInfoNew(len(gen.Mem), a, 0, 0, uint8(w), index2Read(rw), progs)
				if _, ok := memTestInfoMap[rw][w][a]; !ok {
					memTestInfoMap[rw][w][a] = []int{}
				}
				memTestInfoMap[rw][w][a] = append(memTestInfoMap[rw][w][a], len(gen.Mem))
				gen.Mem = append(gen.Mem, ti)
			}
		}
	}
	cls := &pgen.ClsTest{Score: 0}
	for i, m := range gen.Mem {
		for _, ol := range memOverlap(memRegion{addr: m.Addr, width: int(m.Width)}) {
			for _, oIdx := range memTestInfoMap[read2Index(!m.Read)][ol.width][ol.addr] {
				if oIdx < i {
					// already covered
					continue
				}
				wMemIdx := i
				rMemIdx := oIdx
				if m.Read {
					wMemIdx, rMemIdx = rMemIdx, wMemIdx
				}
				nTests := float64(len(gen.Mem[wMemIdx].Progs)) * float64(len(gen.Mem[rMemIdx].Progs))
				cls.Tests = append(cls.Tests, pgen.MemPair{WMemIdx: wMemIdx, RMemIdx: rMemIdx, Score: nTests})
			}
		}
	}
	gen.Cls = append(gen.Cls, *cls)
	for _, cls := range gen.Cls {
		sort.Slice(cls.Tests, func(i, j int) bool {
			return cls.Tests[i].Score < cls.Tests[j].Score
		})
	}
	return gen
}

func genPCAddrCluster(heatMap *MemHeatMap) *pgen.TestPred {
	gen := &pgen.TestPred{
		Mem: []*pgen.MemTestInfo{},
		Cls: []pgen.ClsTest{},
	}
	memTestInfoMap := [2][4]map[uint64][]int{{{}, {}, {}, {}}, {{}, {}, {}, {}}}
	clsMap := map[uint64]map[uint64]map[uint64]map[uint64]*pgen.ClsTest{}
	for rw, _mem := range heatMap.Mem {
		for w, __mem := range _mem {
			for a, info := range __mem {
				for pc, csMap := range info.Progs {
					progs := map[int]bool{}
					for _, csProgs := range csMap {
						for p := range csProgs {
							progs[p] = true
						}
					}
					ti := genMemTestInfoNew(len(gen.Mem), a, pc, 0, uint8(w), index2Read(rw), progs)
					if _, ok := memTestInfoMap[rw][w][a]; !ok {
						memTestInfoMap[rw][w][a] = []int{}
					}
					memTestInfoMap[rw][w][a] = append(memTestInfoMap[rw][w][a], len(gen.Mem))
					gen.Mem = append(gen.Mem, ti)
				}
			}
		}
	}
	for i, m := range gen.Mem {
		for _, ol := range memOverlap(memRegion{addr: m.Addr, width: int(m.Width)}) {
			for _, oIdx := range memTestInfoMap[read2Index(!m.Read)][ol.width][ol.addr] {
				if oIdx < i {
					// already covered
					continue
				}
				wMemIdx := i
				rMemIdx := oIdx
				if m.Read {
					wMemIdx, rMemIdx = rMemIdx, wMemIdx
				}
				wpc := gen.Mem[wMemIdx].PC
				waddr := gen.Mem[wMemIdx].Addr
				rpc := gen.Mem[rMemIdx].PC
				raddr := gen.Mem[rMemIdx].Addr
				if _, ok := clsMap[wpc]; !ok {
					clsMap[wpc] = map[uint64]map[uint64]map[uint64]*pgen.ClsTest{}
				}
				if _, ok := clsMap[wpc][waddr]; !ok {
					clsMap[wpc][waddr] = map[uint64]map[uint64]*pgen.ClsTest{}
				}
				if _, ok := clsMap[wpc][waddr][rpc]; !ok {
					clsMap[wpc][waddr][rpc] = map[uint64]*pgen.ClsTest{}
				}
				if _, ok := clsMap[wpc][waddr][rpc][raddr]; !ok {
					clsMap[wpc][waddr][rpc][raddr] = &pgen.ClsTest{Score: 0.0}
				}
				nTests := float64(len(gen.Mem[wMemIdx].Progs)) * float64(len(gen.Mem[rMemIdx].Progs))
				clsMap[wpc][waddr][rpc][raddr].Score += nTests
				clsMap[wpc][waddr][rpc][raddr].Tests = append(clsMap[wpc][waddr][rpc][raddr].Tests, pgen.MemPair{WMemIdx: wMemIdx, RMemIdx: rMemIdx, Score: nTests})
			}
		}
	}
	for _, waddrMap := range clsMap {
		for _, rpcMap := range waddrMap {
			for _, raddrMap := range rpcMap {
				for _, cls := range raddrMap {
					gen.Cls = append(gen.Cls, *cls)
				}
			}
		}
	}
	sort.Slice(gen.Cls, func(i, j int) bool {
		return gen.Cls[i].Score < gen.Cls[j].Score
	})
	for _, cls := range gen.Cls {
		sort.Slice(cls.Tests, func(i, j int) bool {
			return cls.Tests[i].Score < cls.Tests[j].Score
		})
	}
	return gen

}

func main() {
	flag.Parse()

	genMemtraceMap := *flagGenMemtraceMap
	genNonePred := *flagGenNonePred
	genPCPred := *flagGenPCPred
	genPCAddrPred := *flagGenPCAddrPred
	genPCCallStackPred := *flagGenPCCallStackPred
	genPred := genNonePred || genPCPred || genPCAddrPred || genPCCallStackPred

	if genMemtraceMap {
		numThread := *flagThread
		traceDir := *flagTraceDir
		progDir := *flagProgDir
		mapPath := *flagMemtraceMap

		target, err := prog.GetTarget(runtime.GOOS, runtime.GOARCH)
		if err != nil {
			log.Fatalf("get target fail: %v", err)
		}
		memHeatMap := rsMemHeatmap(numThread, target, ns.RsTable, ns.FdCallTable, ns.NFdCallTable, traceDir, progDir)
		err = util.ToGobFile(memHeatMap, mapPath)
		if err != nil {
			log.Fatalf("cannot encode memory trace map: %v", err)
		}
	} else if genPred {
		mapPath := *flagMemtraceMap
		predPath := *flagPred

		memHeatMap := &MemHeatMap{}
		err := util.FromGobFile(memHeatMap, mapPath)
		if err != nil {
			log.Fatalf("cannot decode memory trace map: %v", err)
		}

		var gen *pgen.TestPred

		if genNonePred {
			gen = genNoneCluster(memHeatMap)
		} else if genPCPred {
			gen = genPCCluster(memHeatMap)
		} else if genPCAddrPred {
			gen = genPCAddrCluster(memHeatMap)
		} else if genPCCallStackPred {
			gen = genPCCallStackCluster(memHeatMap)
		}

		log.Printf("number of clusters: %v", len(gen.Cls))

		err = util.ToJsonFile(gen, predPath)
		if err != nil {
			log.Fatalf("cannot encode prediction: %v", err)
		}
	}

}
