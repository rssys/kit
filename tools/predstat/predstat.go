package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rss/kit/pgen"
)

var (
	flagPred   = flag.String("pred", "", "pred path")
	flagThread = flag.Int("thread", 1, "number of threads (default 1)")
)

func syncSetMap(m []map[int]map[int]bool, mu []sync.Mutex, s int, rr []int) int {
	mIdx := s % len(mu)
	mu[mIdx].Lock()
	defer mu[mIdx].Unlock()
	cnt := 0
	for _, r := range rr {
		if _, ok := m[mIdx][s]; ok {
			if m[mIdx][s][r] {
				continue
			}
			m[mIdx][s][r] = true
		} else {
			m[mIdx][s] = make(map[int]bool)
			m[mIdx][s][r] = true
		}
		cnt++
	}
	return cnt
}

func memPairTestCaseCounter(p *pgen.TestPred, mpChan chan pgen.MemPair, m []map[int]map[int]bool, mu []sync.Mutex, tcCnt, mpDone *uint64) {
	for {
		mp, ok := <-mpChan
		if !ok {
			return
		}
		for _, wp := range p.Mem[mp.WMemIdx].Progs {
			cnt := syncSetMap(m, mu, wp, p.Mem[mp.RMemIdx].Progs)
			atomic.AddUint64(tcCnt, uint64(cnt))
		}
		atomic.AddUint64(mpDone, 1)
	}
}

func main() {
	flag.Parse()
	f, err := os.Open(*flagPred)
	if err != nil {
		log.Fatalf("cannot open prediction file: %v", err)
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	pred := &pgen.TestPred{}
	err = dec.Decode(pred)
	if err != nil {
		log.Fatalf("cannot decode prediction file: %v", err)
	}
	m := []map[int]map[int]bool{}
	mu := []sync.Mutex{}
	// more memory for less contention
	partitionRatio := 1000
	for i := 0; i < *flagThread*partitionRatio; i++ {
		m = append(m, map[int]map[int]bool{})
		mu = append(mu, sync.Mutex{})
	}

	mpDone := uint64(0)
	tcCnt := uint64(0)
	totalMP := 0
	for _, cls := range pred.Cls {
		totalMP += len(cls.Tests)
	}
	go func() {
		for {
			<-time.After(5 * time.Second)
			mpDoneL := atomic.LoadUint64(&mpDone)
			mpDoneRatio := (float64(mpDoneL) / float64(totalMP)) * 100.0
			log.Printf("processed %v/%v (%.2f%%) memory pairs, total test cases = %v...",
				atomic.LoadUint64(&mpDone),
				totalMP,
				mpDoneRatio,
				atomic.LoadUint64(&tcCnt),
			)
		}
	}()
	mpChan := make(chan pgen.MemPair)
	for i := 0; i < *flagThread; i++ {
		go memPairTestCaseCounter(pred, mpChan, m, mu, &tcCnt, &mpDone)
	}
	for _, cls := range pred.Cls {
		for _, mp := range cls.Tests {
			mpChan <- mp
		}
	}
	log.Printf("total test cases = %v...",
		atomic.LoadUint64(&tcCnt),
	)
	close(mpChan)
}
