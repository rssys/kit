package trace

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"reflect"
	"strings"
	"unsafe"

	"github.com/rss/kit/exec"
)

// Provide paths in info json file so other non-golang programs
// can read information from it.

type TraceInfo struct {
	Name         string         `json:"name"`
	Attack       bool           `json:"attack"`
	ScTraceName  string         `json:"sctrace_name"`
	MemTraceName []string       `json:"memtrace_name"`
	MemTraceNum  []int          `json:"memtrace_num"`
	ExecFlags    exec.ExecFlags `json:"exec_flags"`
	Timeout      bool           `json:"timeout"`
	Hanged       bool           `json:"hanged"`
}

func NewTraceInfo(name string, attack, timeout, hanged bool) *TraceInfo {
	return &TraceInfo{Name: name, Attack: attack, Timeout: timeout, Hanged: hanged}
}

func TraceName(name string, attack bool) (string, error) {
	if len(name) == 0 {
		return "", fmt.Errorf("info doesn't have name")
	}
	if attack {
		return name + "_A", nil
	} else {
		return name + "_V", nil
	}
}

func SaveMemtrace(info *TraceInfo, dir string, calls []exec.CallInfo) error {

	base, err := TraceName(info.Name, info.Attack)
	if err != nil {
		return fmt.Errorf("cannot get trace name: %v", err)
	}
	memBase := path.Join(dir, base+".mem")
	for i := 0; i < len(calls); i++ {
		mem := memBase + fmt.Sprintf(".%v", i)
		info.MemTraceNum = append(info.MemTraceNum, calls[i].MemtraceNum)
		info.MemTraceName = append(info.MemTraceName, path.Base(mem))
		err := ioutil.WriteFile(mem, calls[i].MemtraceBuf, 0666)
		if err != nil {
			return fmt.Errorf("cannot save memtrace: %v", err)
		}
	}
	return nil
}

func LoadMemtrace(info *TraceInfo, dir string) ([][]*exec.MemTrace, error) {
	t := [][]*exec.MemTrace{}
	base, err := TraceName(info.Name, info.Attack)
	if err != nil {
		return nil, fmt.Errorf("cannot get trace name: %v", err)
	}
	memBase := path.Join(dir, base+".mem")
	for i, traceNum := range info.MemTraceNum {
		var pkts []exec.RawMemtracePkt
		var pkt exec.RawMemtracePkt

		t = append(t, []*exec.MemTrace{})
		if traceNum == 0 {
			continue
		}
		memPath := memBase + fmt.Sprintf(".%v", i)
		buf, err := ioutil.ReadFile(memPath)
		if err != nil {
			return nil, fmt.Errorf("cannot read trace: %v", err)
		}
		pktSize := int(unsafe.Sizeof(pkt))
		if (len(buf) % pktSize) != 0 {
			return nil, fmt.Errorf("memtrace file size %v is not multiple of %v", len(buf), pktSize)
		}
		hdr := (*reflect.SliceHeader)((unsafe.Pointer(&pkts)))
		hdr.Data = uintptr(unsafe.Pointer(&buf[0]))
		hdr.Len = len(buf) / pktSize
		hdr.Cap = hdr.Len
		cnt := 0
		for j := 0; j < len(pkts); j++ {
			m := pkts[j].ToMemTraces()
			n := 16
			if traceNum-cnt < 16 {
				n = traceNum - cnt
			}
			t[i] = append(t[i], m[:n]...)
			cnt += n
		}
	}
	return t, nil
}

func SaveSCTrace(info *TraceInfo, dir string, scTrace [][]string) error {

	base, err := TraceName(info.Name, info.Attack)
	if err != nil {
		return fmt.Errorf("cannot get trace name: %v", err)
	}
	scPath := path.Join(dir, base+".sc")
	f, err := os.Create(scPath)
	if err != nil {
		return fmt.Errorf("cannot create sc file: %v", err)
	}
	defer f.Close()
	info.ScTraceName = base + ".sc"
	enc := json.NewEncoder(f)
	err = enc.Encode(scTrace)
	if err != nil {
		return fmt.Errorf("cannot encode sc: %v", err)
	}
	return nil
}

func LoadSCTrace(info *TraceInfo, dir string) ([][]string, error) {
	scPath := path.Join(dir, info.ScTraceName)
	f, err := os.Open(scPath)
	if err != nil {
		return nil, fmt.Errorf("cannot load sc file: %v", err)
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	sc := [][]string{}
	err = dec.Decode(&sc)
	if err != nil {
		return nil, fmt.Errorf("cannot decode sc: %v", err)
	}
	return sc, nil
}

func SaveTraceInfo(info *TraceInfo, dir string) error {

	base, err := TraceName(info.Name, info.Attack)
	if err != nil {
		return fmt.Errorf("cannot get trace name: %v", err)
	}
	infoPath := path.Join(dir, base+".json")
	infStr, err := json.MarshalIndent(info, "", "\t")
	if err != nil {
		return fmt.Errorf("cannot convert info to json: %v", err)
	}
	err = ioutil.WriteFile(infoPath, []byte(infStr), 0666)
	if err != nil {
		return fmt.Errorf("cannot save info: %v", err)
	}
	return nil
}

func LoadTraceInfoByProgName(dir, progName string, attack bool) (*TraceInfo, error) {
	traceName, err := TraceName(progName, attack)
	if err != nil {
		return nil, fmt.Errorf("cannot get trace name: %v", err)
	}
	info, err := LoadTraceInfoByTraceName(dir, traceName)
	if err != nil {
		return nil, err
	}
	return info, nil
}

func LoadTraceInfoByTraceName(dir, traceName string) (*TraceInfo, error) {
	infoPath := path.Join(dir, traceName+".json")
	info := &TraceInfo{}
	infoBytes, err := ioutil.ReadFile(infoPath)
	if err != nil {
		return nil, fmt.Errorf("read info file: %v", err)
	}
	err = json.Unmarshal(infoBytes, info)
	if err != nil {
		return nil, fmt.Errorf("parse json: %v", err)
	}
	return info, nil
}

func AllTraceInfoNames(dir string) ([]string, error) {
	traceFiles, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("open trace dir: %v", err)
	}
	names := make([]string, 0, len(traceFiles)/3)
	for _, f := range traceFiles {
		l := strings.Split(f.Name(), ".")
		name := l[0]
		ty := l[1]
		if ty == "json" {
			names = append(names, name)
		}
	}
	return names, nil
}
