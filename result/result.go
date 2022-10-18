package result

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path"
	"time"

	"github.com/google/syzkaller/prog"
	"github.com/rss/kit/pgen"
	"github.com/rss/kit/trace"
)

type TestResult struct {
	TimeStamp        string               `json:"time_stamp"`
	TestIdx          int                  `json:"test_idx"`
	ClsIdx           int                  `json:"cls_idx"`
	ClsMemIdx        int                  `json:"cls_mem_idx"`
	ClsMemAProgIdx   int                  `json:"cls_mem_a_prog_idx"`
	ClsMemVProgIdx   int                  `json:"cls_mem_v_prog_idx"`
	APredPC          string               `json:"a_pred_pc"`
	APredAddr        string               `json:"a_pred_addr"`
	APredAddrLen     uint8                `json:"a_pred_addr_len"`
	VPredPC          string               `json:"v_pred_pc"`
	VPredAddr        string               `json:"v_pred_addr"`
	VPredAddrLen     uint8                `json:"v_pred_addr_len"`
	Interleave       bool                 `json:"interleave"`
	VPause           uint8                `json:"v_pause"`
	ADiff            []*trace.SCTraceDiff `json:"adiff"`
	VDiff            []*trace.SCTraceDiff `json:"vdiff"`
	Timeout          bool                 `json:"timeout"`
	AProgHanged      bool                 `json:"a_prog_hanged"`
	VProgHanged      bool                 `json:"v_prog_hanged"`
	AProgName        string               `json:"a_prog_name"`
	VProgName        string               `json:"v_prog_name"`
	AProg            string               `json:"a_prog"`
	AProgMini        string               `json:"a_prog_mini"`
	ACallDiag        []int                `json:"a_call_diag"`
	VCallDiag        []int                `json:"v_call_diag"`
	VProg            string               `json:"v_prog"`
	AExecFlag        uint64               `json:"a_exec_flag"`
	VExecFlag        uint64               `json:"v_exec_flag"`
	AProgMiniSCTrace string               `json:"a_prog_mini_sctrace"`
	AProgSCTrace     string               `json:"a_prog_sctrace"`
	VProgSCTrace     string               `json:"v_prog_sctrace"`
	VProgPrevSCTrace string               `json:"v_prog_prev_sctrace"`
	AProgPrevSCTrace string               `json:"a_prog_prev_sctrace"`
}

const TimeStampFormat string = "2006/01/02 15:04:05"

func NewTestResult(test *pgen.ProgPair, aProgMini *prog.Prog, aCallDiag, vCallDiag []int, testIdx, clsIdx, clsMemIdx, clsMemAProgIdx, clsMemVProgIdx int, aPredPC, aPredAddr, vPredPC, vPredAddr uint64, aPredAddrLen, vPredAddrLen uint8, interleave bool, vPause uint8, aExecFlag, vExecFlag uint64, timeout, aProgHanged, vProgHanged bool, adiff, vdiff []*trace.SCTraceDiff, aProgSCTrace, AProgMiniSCTrace, vProgSCTrace, aProgPrevSCTrace, vProgPrevSCTrace *trace.ProgSCTrace) *TestResult {
	res := &TestResult{
		TimeStamp:      time.Now().Format(TimeStampFormat),
		ACallDiag:      aCallDiag,
		VCallDiag:      vCallDiag,
		TestIdx:        testIdx,
		ClsIdx:         clsIdx,
		ClsMemIdx:      clsMemIdx,
		ClsMemAProgIdx: clsMemAProgIdx,
		ClsMemVProgIdx: clsMemVProgIdx,
		APredPC:        fmt.Sprintf("0x%x", aPredPC),
		APredAddr:      fmt.Sprintf("0x%x", aPredAddr),
		VPredPC:        fmt.Sprintf("0x%x", vPredPC),
		VPredAddr:      fmt.Sprintf("0x%x", vPredAddr),
		APredAddrLen:   aPredAddrLen,
		VPredAddrLen:   vPredAddrLen,
		Interleave:     interleave,
		VPause:         vPause,
		ADiff:          adiff,
		VDiff:          vdiff,
		Timeout:        timeout,
		AProgHanged:    aProgHanged,
		VProgHanged:    vProgHanged,
		AProgName:      test.A.Meta.Name,
		VProgName:      test.V.Meta.Name,
		AProg:          string(test.A.P.Serialize()),
		VProg:          string(test.V.P.Serialize()),
		AExecFlag:      aExecFlag,
		VExecFlag:      vExecFlag,
	}
	if aProgMini != nil {
		res.AProgMini = string(aProgMini.Serialize())
	}
	if aProgSCTrace != nil {
		res.AProgSCTrace = string(aProgSCTrace.DeterminSerialze())
	}
	if AProgMiniSCTrace != nil {
		res.AProgMiniSCTrace = string(AProgMiniSCTrace.RawSerialze())
	}
	if vProgSCTrace != nil {
		res.VProgSCTrace = string(vProgSCTrace.DeterminSerialze())
	}
	if aProgPrevSCTrace != nil {
		res.AProgPrevSCTrace = string(aProgPrevSCTrace.DeterminSerialze())
	}
	if vProgPrevSCTrace != nil {
		res.VProgPrevSCTrace = string(vProgPrevSCTrace.DeterminSerialze())
	}
	return res
}

func SerializeTestResult(resultTmpDir string, res *TestResult) error {
	resStr, err := json.MarshalIndent(res, "", "\t")
	if err != nil {
		return fmt.Errorf("cannot serialize results: %v", err)
	}
	var resPath string
	if res.Interleave {
		resPath = path.Join(resultTmpDir, fmt.Sprintf("%v_%v_%v.json", res.AProgName, res.VProgName, res.VPause))
	} else {
		resPath = path.Join(resultTmpDir, fmt.Sprintf("%v_%v.json", res.AProgName, res.VProgName))
	}
	err = ioutil.WriteFile(resPath, resStr, 0666)
	if err != nil {
		return fmt.Errorf("cannot write results: %v", err)
	}
	return nil
}

func LoadResult(path string) (*TestResult, error) {
	res := &TestResult{}
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read from file: %v", err)
	}
	err = json.Unmarshal(data, res)
	if err != nil {
		return nil, fmt.Errorf("cannot parse file: %v", err)
	}
	return res, nil
}
