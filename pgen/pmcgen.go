package pgen

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strconv"

	"github.com/google/syzkaller/prog"
)

type PmcPredPCEntry struct {
	WPC    uint64 `json:"w_pc"`
	RPC    uint64 `json:"r_pc"`
	WProgs []int  `json:"w_progs"`
	RProgs []int  `json:"r_progs"`
	Cnt    int    `json:"cnt"`
}

type PmcPredPC struct {
	Entries []PmcPredPCEntry `json:"entries"`
}

type PmcPred map[int]map[int]bool

type pmcPredPCEntryGenCtx struct {
	wProgsIdx int
	rProgsIdx int
}

type pmcPredPCGenCtx struct {
	pred          *PmcPredPC
	visited       map[int]map[int]bool
	entryCtx      []pmcPredPCEntryGenCtx
	entryCand     []int
	entryCandIdx  int
	entryCandNext []int
}

type PmcPredPCGenerator struct {
	target     *prog.Target
	pred       *PmcPredPC
	profileDir string
	programDir string
	genCtx     pmcPredPCGenCtx
}

func (ctx *pmcPredPCGenCtx) nextEntry() {
	if ctx.entryCandIdx == len(ctx.entryCand)-1 {
		ctx.entryCandIdx = 0
		ctx.entryCand = ctx.entryCandNext
		ctx.entryCandNext = make([]int, 0)
	} else {
		ctx.entryCandIdx++
	}
}

func (ctx *pmcPredPCGenCtx) generate() (w int, r int, done bool) {
	for {
		if len(ctx.entryCand) == 0 {
			return -1, -1, true
		}
		entryIdx := ctx.entryCand[ctx.entryCandIdx]
		entry := &ctx.pred.Entries[entryIdx]
		entryCtx := &ctx.entryCtx[entryIdx]
		vis := false
		done := false
		wIdx := entryCtx.wProgsIdx
		rIdx := entryCtx.rProgsIdx
		w = entry.WProgs[wIdx]
		r = entry.RProgs[rIdx]
		if _, ok := ctx.visited[w][r]; ok {
			vis = true
		}
		if rIdx == len(entry.RProgs)-1 {
			if wIdx == len(entry.WProgs)-1 {
				done = true
			} else {
				entryCtx.rProgsIdx = 0
				entryCtx.wProgsIdx++
			}
		} else {
			entryCtx.rProgsIdx++
		}
		if vis {
			// try to generate another pair in current entry
			if done {
				ctx.nextEntry()
				continue
			} else {
				continue
			}
		} else {
			// return pair and move to next entry
			if _, ok := ctx.visited[w]; !ok {
				ctx.visited[w] = make(map[int]bool)
			}
			ctx.visited[w][r] = true
			ctx.nextEntry()
			if !done {
				ctx.entryCandNext = append(ctx.entryCandNext, entryIdx)
			}
			return w, r, false
		}
	}
}

func InitPmcPredPCGenerator(target *prog.Target, profileDir, programDir string, predsPath string) (*PmcPredPCGenerator, error) {
	gen := &PmcPredPCGenerator{profileDir: profileDir, programDir: programDir, target: target}
	f, err := os.Open(predsPath)
	if err != nil {
		log.Fatalf("cannot open prediction file: %v", err)
	}
	dec := json.NewDecoder(f)
	pred := &PmcPredPC{}
	err = dec.Decode(pred)
	gen.pred = pred
	gen.genCtx = pmcPredPCGenCtx{
		pred:         pred,
		visited:      make(map[int]map[int]bool),
		entryCandIdx: 0,
	}
	for i := 0; i < len(pred.Entries); i++ {
		gen.genCtx.entryCand = append(gen.genCtx.entryCand, i)
		gen.genCtx.entryCtx = append(gen.genCtx.entryCtx, pmcPredPCEntryGenCtx{wProgsIdx: 0, rProgsIdx: 0})
	}
	if err != nil {
		log.Fatalf("cannot decode prediction file: %v", err)
	}
	return gen, nil
}

func (gen *PmcPredPCGenerator) Generate() (*ProgPair, error) {
	for {
		pair := &ProgPair{
			A: &ProgGen{},
			V: &ProgGen{},
		}
		a, v, done := gen.genCtx.generate()
		if done {
			return nil, nil
		}
		aName := strconv.FormatInt(int64(a), 10)
		aPath := path.Join(gen.programDir, aName)
		aProgBytes, err := ioutil.ReadFile(aPath)
		if err != nil {
			return nil, err
		}
		pair.A.P, err = gen.target.Deserialize(aProgBytes, prog.NonStrict)
		if err != nil {
			continue
		}
		pair.A.Meta = &ProgMeta{Name: aName}

		vName := strconv.FormatInt(int64(v), 10)
		vPath := path.Join(gen.programDir, vName)
		vProgBytes, err := ioutil.ReadFile(vPath)
		if err != nil {
			return nil, err
		}
		pair.V.P, err = gen.target.Deserialize(vProgBytes, prog.NonStrict)
		if err != nil {
			continue
		}
		pair.V.Meta = &ProgMeta{Name: vName}
		return pair, nil
	}
}

func (gen *PmcPredPCGenerator) Log() string {
	return ""
}
