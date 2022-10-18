package main

import (
	"encoding/json"
	"flag"
	"log"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rss/kit/pgen"
	"github.com/rss/kit/trace"
)

var (
	flagTraceDir = flag.String("trace_dir", "", "trace direcotry")
	flagRandPath = flag.String("rand_path", "", "random prediction path")
	flagNum      = flag.Int("num", 500000, "number of test cases for full random ")
)

func GetAllProgs(traceDir string) map[int]bool {
	traceNames, err := trace.AllTraceInfoNames(traceDir)
	if err != nil {
		log.Fatalf("cannot get trace names: %v", err)
	}
	allProg := map[int]bool{}
	for _, name_prefix := range traceNames {
		name := strings.Split(name_prefix, `_`)[0]
		progNum, err := strconv.Atoi(name)
		if err != nil {
			log.Fatalf("cannot convert program name %v to integer: %v", name, err)
		}
		allProg[progNum] = true
	}
	return allProg
}

func genMemTestInfoNew(idx int, addr, pc uint64, width uint8, read bool, progMap map[int]bool) *pgen.MemTestInfo {
	progs := []int{}
	for p := range progMap {
		progs = append(progs, p)
	}
	return &pgen.MemTestInfo{
		Addr:  addr,
		PC:    pc,
		Width: width,
		Read:  read,
		Progs: progs,
		Idx:   idx,
	}
}

func genMemRelGenFullRand(allProg map[int]bool, num int) *pgen.TestPred {
	gen := &pgen.TestPred{
		Mem: []*pgen.MemTestInfo{},
		Cls: []pgen.ClsTest{},
	}
	nProgs := len(allProg)
	for p := range allProg {
		pm := map[int]bool{p: true}
		gen.Mem = append(gen.Mem, genMemTestInfoNew(len(gen.Mem), 0, 0, 1, true, pm))
	}
	gen.Cls = []pgen.ClsTest{
		{},
	}
	log.Printf("random: total test programs: %v", (uint64)(nProgs))
	log.Printf("random: restrict test cases to: %v", num)
	vis := map[int]map[int]bool{}
	cnt := 0
	rand.Seed(time.Now().UnixNano())
	for {
		aIdx := rand.Int() % nProgs
		vIdx := rand.Int() % nProgs
		if vis[aIdx][vIdx] {
			continue
		}
		if _, ok := vis[aIdx]; !ok {
			vis[aIdx] = map[int]bool{}
		}
		vis[aIdx][vIdx] = true
		gen.Cls[0].Tests = append(gen.Cls[0].Tests, pgen.MemPair{
			WMemIdx: aIdx,
			RMemIdx: vIdx,
		})
		cnt++
		if cnt%10000 == 0 {
			log.Printf("Full rand: generate %v test cases...", cnt)
		}
		if cnt == num {
			break
		}
	}
	return gen
}

func serialize(gen *pgen.TestPred, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent(" ", "\t")
	err = enc.Encode(gen)
	return err
}
func main() {
	flag.Parse()
	traceDir := *flagTraceDir
	numTests := *flagNum

	allProg := GetAllProgs(traceDir)
	genRand := genMemRelGenFullRand(allProg, numTests)

	err := serialize(genRand, *flagRandPath)
	if err != nil {
		log.Fatalf("cannot encode full rand predictions: %v", err)
	}
}
