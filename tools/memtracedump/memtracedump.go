package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"strings"

	"github.com/rss/kit/exec"
	"github.com/rss/kit/trace"
)

var (
	flagTrace   = flag.String("trace", "", "trace path, exclude .json")
	flagCallIdx = flag.Int("call_idx", -1, "call index")
	flagOut     = flag.String("out", "", "output path")
)

func memtraceToString(t *exec.MemTrace) string {
	s := ""
	switch t.Type {
	case exec.MemtraceWrite:
		s = fmt.Sprintf("w, pc = 0x%x, addr = 0x%x, len = %d", t.PC, t.Addr, t.Len)
	case exec.MemtraceRead:
		s = fmt.Sprintf("r, pc = 0x%x, addr = 0x%x, len = %d", t.PC, t.Addr, t.Len)
	case exec.MemtraceRet:
		s = fmt.Sprintf("ret, pc = 0x%x", t.PC)
	case exec.MemtraceCall:
		s = fmt.Sprintf("call, pc = 0x%x", t.PC)
	default:
		log.Fatalf("invalid memory trace type %v", t.Type)
	}
	return s
}

func main() {
	flag.Parse()
	trName := path.Base(*flagTrace)
	trDir := path.Dir(*flagTrace)
	trInfo, err := trace.LoadTraceInfoByTraceName(trDir, trName)
	if err != nil {
		log.Fatalf("cannot open trace: %v", err)
	}
	memTr, err := trace.LoadMemtrace(trInfo, trDir)
	if err != nil {
		log.Fatalf("cannot load memory trace: %v", err)
	}
	callIdx := *flagCallIdx
	if len(memTr) <= callIdx {
		log.Fatalf("call index %v >= %v", callIdx, len(memTr))
	}
	of, err := os.OpenFile(*flagOut, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		log.Fatalf("cannot create file: %v", err)
	}
	arr := []string{}
	for _, t := range memTr[callIdx] {
		arr = append(arr, memtraceToString(t))
	}
	of.WriteString(strings.Join(arr, "\n"))
	of.Close()
}
