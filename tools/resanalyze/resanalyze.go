package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/google/syzkaller/prog"
	"github.com/rss/kit/ns"
	"github.com/rss/kit/result"
	"github.com/rss/kit/trace"
)

var (
	flagProgDir       = flag.String("prog_dir", "", "program directory")
	flagResultDir     = flag.String("result_dir", "", "result directory")
	flagResultCluster = flag.String("result_cluster", "", "result cluster path")
)

// r_call -> s_call -> diff node path -> diff value -> result name
type ClusterMap map[string]map[string]map[string]map[string][]ResultInfo

type ResultInfo struct {
	TimeStamp string `json:"time_stamp"`
	Name      string `json:"name"`
}

type ClusterResult struct {
	CallClusters []*RCallClusterResult `json:"r_call_clusters"`
}

type RCallClusterResult struct {
	RCallName     string                `json:"r_call_name"`
	Size          int                   `json:"size"`
	SCallClusters []*SCallClusterResult `json:"s_call_clusters"`
}

type SCallClusterResult struct {
	SCallName        string                   `json:"s_call_name"`
	Size             int                      `json:"size"`
	NodePathClusters []*NodePathClusterResult `json:"node_path_clusters"`
}

type NodePathClusterResult struct {
	NodePath        string                   `json:"node_path"`
	DiffValClusters []*DiffVallClusterResult `json:"diff_val_clusters"`
}

type DiffVallClusterResult struct {
	DiffVal string       `json:"diff_val"`
	Names   []ResultInfo `json:"names"`
}

func (c ClusterMap) Serialize() ClusterResult {
	clusterRes := ClusterResult{}
	for call, sCallMap := range c {
		rCallRes := RCallClusterResult{RCallName: call, Size: 0}
		for sCall, ndMap := range sCallMap {
			sCallRes := SCallClusterResult{SCallName: sCall, Size: 0}
			for nodePath, nodePathMap := range ndMap {
				nodePathRes := NodePathClusterResult{NodePath: nodePath}
				for diffVal, names := range nodePathMap {
					diffValRes := DiffVallClusterResult{DiffVal: diffVal, Names: names}
					sort.Slice(diffValRes.Names, func(i, j int) bool {
						return diffValRes.Names[i].TimeStamp < diffValRes.Names[j].TimeStamp
					})
					nodePathRes.DiffValClusters = append(nodePathRes.DiffValClusters, &diffValRes)
					rCallRes.Size += len(names)
					sCallRes.Size += len(names)
				}
				sCallRes.NodePathClusters = append(sCallRes.NodePathClusters, &nodePathRes)
			}
			rCallRes.SCallClusters = append(rCallRes.SCallClusters, &sCallRes)
		}
		clusterRes.CallClusters = append(clusterRes.CallClusters, &rCallRes)
	}
	return clusterRes
}

var total_rep = 0

func (c ClusterMap) Add(target *prog.Target, progDir string, res *result.TestResult, resName string) error {
	if res.Timeout || res.VProgHanged {
		return nil
	}
	if len(res.ACallDiag) == 0 {
		return nil
	}
	aProgBytes, err := ioutil.ReadFile(path.Join(progDir, res.AProgName))
	if err != nil {
		return fmt.Errorf("cannot read program file: %v", err)
	}
	aProg, err := target.Deserialize(aProgBytes, prog.NonStrict)
	if err != nil {
		return fmt.Errorf("cannot deserailze program file: %v", err)
	}
	vProgBytes, err := ioutil.ReadFile(path.Join(progDir, res.VProgName))
	if err != nil {
		return fmt.Errorf("cannot read program file: %v", err)
	}
	vProg, err := target.Deserialize(vProgBytes, prog.NonStrict)
	if err != nil {
		return fmt.Errorf("cannot deserailze program file: %v", err)
	}

	// Only keep the first interfered receiver system call since the rest
	// interfered calls are usually the secondary results of the first one,
	// e.g., file descritor number shift.
	res.VDiff = res.VDiff[:1]

	va := ns.ResourceCallAnalysis(vProg)
	aa := ns.ResourceCallAnalysis(aProg)

	diffs := []*trace.SCTraceDiff{}
	aCalls := []string{}
	vCalls := []string{}

	tmpMap := map[int]int{}
	for i, aCallIdx := range res.ACallDiag {
		vCallIdx := res.VCallDiag[i]
		if _, ok := tmpMap[vCallIdx]; !ok {
			tmpMap[vCallIdx] = -1
		}
		if tmpMap[vCallIdx] < aCallIdx {
			tmpMap[vCallIdx] = aCallIdx
		}
	}
	newACalls := []int{}
	newVCalls := []int{}
	for vc, ac := range tmpMap {
		newVCalls = append(newVCalls, vc)
		newACalls = append(newACalls, ac)
	}

	for i, aCallIdx := range newACalls {
		aCall := ""
		vCall := ""
		vCallIdx := newVCalls[i]
		callMatchInfo, ok := va[vCallIdx]
		if !ok {
			continue
		}
		maRsMap := map[string]bool{}
		for _, defUse := range callMatchInfo.RsInfo {
			maRsMap[defUse.RsName] = true
		}
		maRsArr := []string{}
		for rs := range maRsMap {
			maRsArr = append(maRsArr, rs)
		}
		sort.Strings(maRsArr)
		maRsName := strings.Join(maRsArr, "|")
		vCall = callMatchInfo.Name + ":" + maRsName
		if callMatchInfo, ok := aa[aCallIdx]; ok {
			maRsMap := map[string]bool{}
			for _, defUse := range callMatchInfo.RsInfo {
				maRsMap[defUse.RsName] = true
			}
			maRsArr := []string{}
			for rs := range maRsMap {
				maRsArr = append(maRsArr, rs)
			}
			sort.Strings(maRsArr)
			maRsName := strings.Join(maRsArr, "|")
			aCall = callMatchInfo.Name + ":" + maRsName
		} else {
			aCall = aProg.Calls[aCallIdx].Meta.Name
		}
		for _, diff := range res.VDiff {
			if diff.CallIdx != vCallIdx {
				continue
			}
			diffs = append(diffs, diff)
			aCalls = append(aCalls, aCall)
			vCalls = append(vCalls, vCall)
		}

	}

	for i, diff := range diffs {
		vCall := vCalls[i]
		aCall := aCalls[i]
		nodePath := diff.NodePath
		diffVal := diff.T
		if _, ok := c[vCall][aCall][nodePath][diffVal]; !ok {
			if _, ok := c[vCall][aCall][nodePath]; !ok {
				if _, ok := c[vCall][aCall]; !ok {
					if _, ok := c[vCall]; !ok {
						c[vCall] = make(map[string]map[string]map[string][]ResultInfo)
					}
					c[vCall][aCall] = make(map[string]map[string][]ResultInfo)
				}
				c[vCall][aCall][nodePath] = make(map[string][]ResultInfo)
			}
			c[vCall][aCall][nodePath][diffVal] = []ResultInfo{}
		}
		c[vCall][aCall][nodePath][diffVal] = append(c[vCall][aCall][nodePath][diffVal], ResultInfo{Name: resName, TimeStamp: res.TimeStamp})
		total_rep++
	}
	return nil

}

func main() {
	flag.Parse()
	cluster := ClusterMap{}
	files, err := ioutil.ReadDir(*flagResultDir)
	if err != nil {
		log.Fatalf("cannot list directory: %v", err)
	}
	target, err := prog.GetTarget(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		log.Fatalf("cannot get target: %v", err)
	}
	printEvery := 50
	// read all results
	resArr := []*result.TestResult{}
	resNameArr := []string{}
	filteredResArr := []*result.TestResult{}
	filteredResNameArr := []string{}
	earliestTs := time.Now()
	for i, fi := range files {
		var res result.TestResult
		resultPath := path.Join(*flagResultDir, fi.Name())
		resultBytes, err := ioutil.ReadFile(resultPath)
		if err != nil {
			log.Fatalf("cannot read result file: %v", err)
		}
		err = json.Unmarshal(resultBytes, &res)
		if err != nil {
			log.Fatalf("cannot unmarshal result file: %v", err)
		}
		resArr = append(resArr, &res)
		resNameArr = append(resNameArr, fi.Name())
		ts, err := time.Parse(result.TimeStampFormat, res.TimeStamp)
		if err != nil {
			log.Fatalf("cannot parse time stamp: %v", err)
		}
		if ts.Before(earliestTs) {
			earliestTs = ts
		}
		if i%printEvery == 0 {
			log.Printf("reading %%%v(%v/%v) files...", 100.0*float64(i)/float64(len(files)), i, len(files))
		}
	}
	// time filter
	for i, res := range resArr {
		filteredResArr = append(filteredResArr, res)
		filteredResNameArr = append(filteredResNameArr, resNameArr[i])
		if i%printEvery == 0 {
			log.Printf("filtering %%%v(%v/%v) results...", 100.0*float64(i)/float64(len(resArr)), i, len(resArr))
		}
	}
	// processing
	for i, res := range filteredResArr {
		err := cluster.Add(target, *flagProgDir, res, filteredResNameArr[i])
		if err != nil {
			log.Fatalf("cannot add result file to cluster: %v", err)
		}
		if i%printEvery == 0 {
			log.Printf("process %%%v(%v/%v) results...", 100.0*float64(i)/float64(len(filteredResArr)), i, len(filteredResArr))
		}
	}
	r_cls_cnt := 0
	rs_cls_cnt := 0
	for _, c := range cluster {
		for range c {
			rs_cls_cnt++
		}
		r_cls_cnt++
	}
	log.Printf("receiver cluster: %v", r_cls_cnt)
	log.Printf("receiver-sender cluster: %v", rs_cls_cnt)
	log.Printf("total report: %v", total_rep)
	clusterRes := cluster.Serialize()
	f, err := os.Create(*flagResultCluster)
	if err != nil {
		log.Fatalf("cannot create result cluster file: %v", err)

	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent(" ", "\t")
	err = enc.Encode(clusterRes)
	if err != nil {
		log.Fatalf("cannot create encode result cluster: %v", err)
	}
}
