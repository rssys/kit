package ns

import (
	"log"
	"runtime"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

type NSType int

const (
	NetNS = (NSType)(iota)
	IPCNS
	MntNS
	PidNS
	UserNS
)

type ResourceInfoTable map[*prog.ResourceDesc]bool

// call signature -> call description
type FdDefCallTable map[*prog.Syscall][]*CallDesc

// call signature -> call description
type NonFdCallTable map[*prog.Syscall][]*CallDesc

func GenResourcesInfoTable(target *prog.Target, spec map[NSType]SpecDescription) (ResourceInfoTable, FdDefCallTable, NonFdCallTable) {
	fdNameTable := make(ResourceInfoTable)
	fdDefCallTable := make(FdDefCallTable)
	nonFdCallTable := make(NonFdCallTable)
	fdNameMap := map[string]bool{}
	for _, desc := range spec {
		for _, name := range desc.FdNames {
			fdNameMap[name] = true
		}
		for _, callDesc := range desc.FdDefCall {
			if c, ok := target.SyscallMap[callDesc.CallName]; ok {
				if _, ok := fdDefCallTable[c]; !ok {
					fdDefCallTable[c] = []*CallDesc{}
				}
				fdDefCallTable[c] = append(fdDefCallTable[c], &callDesc)
			}
		}
		for _, callDesc := range desc.NonFdCall {
			if c, ok := target.SyscallMap[callDesc.CallName]; ok {
				if _, ok := nonFdCallTable[c]; !ok {
					nonFdCallTable[c] = []*CallDesc{}
				}
				nonFdCallTable[c] = append(nonFdCallTable[c], &callDesc)
			}
		}
	}
	for _, r := range target.Resources {
		if fdNameMap[r.Name] {
			fdNameTable[r] = true
		}
	}
	return fdNameTable, fdDefCallTable, nonFdCallTable
}

type RsDefUseInfo struct {
	RsName string
	RsRef  *RsDefUseInfo // nil when using special values
	Def    bool
	Dup    bool
	Use    bool
}

type CallMatchInfo struct {
	Name   string
	RsInfo []*RsDefUseInfo
}

type ResourceTable map[*prog.ResultArg]*RsDefUseInfo
type ProgAnalyzeRes map[int]*CallMatchInfo

func useResourceArgs(a *prog.ResultArg, table ResourceTable) (bool, *RsDefUseInfo) {
	res := a
	for res != nil {
		if info, ok := table[res]; ok {
			return true, info
		}
		res = res.Res
	}
	return false, nil
}

func ResourceCallAnalysis(p *prog.Prog) ProgAnalyzeRes {
	m := ProgAnalyzeRes{}
	rsArgs := ResourceTable{}
	for i, call := range p.Calls {
		switch call.Meta.Name {
		case `dup`, `dup2`, `dup3`, `fcntl$dupfd`:
			// update resource table
			// Don't label this call as resource def since it is not creating
			// a new reousrce, instead just add a new reference to existing one
			a := call.Args[0].(*prog.ResultArg)
			if use, rsDefUseInfo := useResourceArgs(a, rsArgs); use {
				newRsDefUseInfo := &RsDefUseInfo{
					RsName: rsDefUseInfo.RsName,
					RsRef:  rsDefUseInfo,
					Dup:    true,
				}
				rsArgs[call.Ret] = newRsDefUseInfo
				if _, ok := m[i]; !ok {
					m[i] = &CallMatchInfo{Name: call.Meta.Name}
				}
				m[i].RsInfo = append(m[i].RsInfo, newRsDefUseInfo)
				continue
			}
		}
		prog.ForeachArg(call, func(arg prog.Arg, ctx *prog.ArgCtx) {
			switch ty := arg.Type().(type) {
			case *prog.ResourceType:
				a := arg.(*prog.ResultArg)
				if a.Dir() == prog.DirIn {
					// check resource use
					if use, rsDefUseInfo := useResourceArgs(a, rsArgs); use {
						if _, ok := m[i]; !ok {
							m[i] = &CallMatchInfo{Name: call.Meta.Name}
						}
						// use def resource
						m[i].RsInfo = append(m[i].RsInfo, &RsDefUseInfo{
							RsName: rsDefUseInfo.RsName,
							RsRef:  rsDefUseInfo,
							Use:    true,
						})
					} else if RsTable[ty.Desc] {
						// use resource special value
						for _, sv := range ty.SpecialValues() {
							if a.Val == sv {
								if _, ok := m[i]; !ok {
									m[i] = &CallMatchInfo{Name: call.Meta.Name}
								}
								m[i].RsInfo = append(m[i].RsInfo, &RsDefUseInfo{
									RsName: ty.Desc.Name,
									Use:    true,
								})
							}
						}
					}
				} else if a.Dir() == prog.DirOut {
					// check resource def
					if RsTable[ty.Desc] {
						newRsDefUseInfo := &RsDefUseInfo{
							RsName: ty.Desc.Name,
							Def:    true,
						}
						rsArgs[a] = newRsDefUseInfo
						if _, ok := m[i]; !ok {
							m[i] = &CallMatchInfo{Name: call.Meta.Name}
						}
						m[i].RsInfo = append(m[i].RsInfo, newRsDefUseInfo)
					}
				}
			}

		})
		if callDescArr, ok := FdCallTable[call.Meta]; ok {
			for _, callDesc := range callDescArr {
				if callDesc.CallName == call.Meta.Name && callDesc.Checker(call) {
					if _, ok := m[i]; !ok {
						m[i] = &CallMatchInfo{Name: call.Meta.Name}
					}
					newInfo := &RsDefUseInfo{
						RsName: "fd$" + callDesc.GetName(call),
						Def:    true,
					}
					// add to arg table to trace use
					rsArgs[call.Ret] = newInfo
					m[i].RsInfo = append(m[i].RsInfo, newInfo)
				}
			}
		}
		if callDescArr, ok := NFdCallTable[call.Meta]; ok {
			for _, callDesc := range callDescArr {
				if callDesc.CallName == call.Meta.Name && callDesc.Checker(call) {
					if _, ok := m[i]; !ok {
						m[i] = &CallMatchInfo{}
					}
					m[i].Name = callDesc.GetName(call)
				}
			}
		}

	}
	return m
}

// Naive interleave algorithm:
// Interleaves only when victim system call is resource related
// Probably we could involve memory trace.
func Interleave(vp *prog.Prog) []uint8 {
	vpPause := []uint8{}
	a := ResourceCallAnalysis(vp)
	for call := range a {
		vpPause = append(vpPause, uint8(call))
	}
	return vpPause
}

var RsTable ResourceInfoTable
var FdCallTable FdDefCallTable
var NFdCallTable NonFdCallTable

func init() {
	target, err := prog.GetTarget(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		log.Fatalf("cannot get program target: %v", err)
	}
	RsTable, FdCallTable, NFdCallTable = GenResourcesInfoTable(target, ResourceSpec)
}
