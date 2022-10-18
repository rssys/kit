package ns

import (
	"runtime"
	"testing"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func TestResourceCallAnalysis(t *testing.T) {
	// rsNames := map[NSType]SpecDescription{
	// 	NetNS: {
	// 		FdNames: []string{
	// 			"sock_unix",
	// 			"sock_alg",
	// 			"genl_tipc_family_id",
	// 			`genl_ipvs_family_id`,
	// 		},
	// 		FdDefCall: []CallDesc{
	// 			{
	// 				CallName: `openat$procfs`,
	// 				Checker: func(c *prog.Call) bool {
	// 					dataRes := c.Args[1].(*prog.PointerArg).Res
	// 					if dataRes == nil {
	// 						return false
	// 					}
	// 					fn := string(dataRes.(*prog.DataArg).Data())
	// 					fmt.Printf("proc = %v\n", fn)
	// 					return strings.Contains(fn, `sysvipc/`)
	// 				},
	// 			},
	// 			{
	// 				CallName: `syz_open_procfs`,
	// 				Checker: func(c *prog.Call) bool {
	// 					dataRes := c.Args[1].(*prog.PointerArg).Res
	// 					if dataRes == nil {
	// 						return false
	// 					}
	// 					fn := string(dataRes.(*prog.DataArg).Data())
	// 					fmt.Printf("proc = %v\n", fn)
	// 					return strings.Contains(fn, `net/`)
	// 				},
	// 			},
	// 		},
	// 	},
	// }
	progStrs := []string{
		`r0 = socket$unix(0x1, 0x2, 0x0)
r1 = openat$procfs(0xffffffffffffff9c, &(0x7f00000004c0)='/proc/asound/seq/clients\x00', 0x0, 0x0)
openat$procfs(0xffffff9c, 0x0, 0x0, 0x0)
r3 = syz_open_procfs(0x0, &(0x7f0000000040)='net/snmp\x00')
r2 = dup2(r0, r1)
connect$unix(r2, &(0x7f0000000040)=@file={0x0, './file0\x00'}, 0x6e)
close(r1)
close(r2)
close(r3)`,
		`dup2(0xffffffffffffffff, 0xffffffffffffffff)`,
		`accept4$alg(0xffffffffffffffff, 0x0, 0x0, 0x400)`,
		`r0 = socket$nl_generic(0x10, 0x3, 0x10)
r1 = syz_genetlink_get_family_id$tipc(&(0x7f0000000040)='TIPC\x00', 0xffffffffffffffff)
sendmsg$TIPC_CMD_SET_NODE_ADDR(r0, &(0x7f0000000100)={&(0x7f0000000000), 0xc, &(0x7f00000000c0)={&(0x7f0000000140)={0x24, r1, 0x1, 0x0, 0x0, {{}, {}, {0x8}}}, 0x24}}, 0x0)`,
		`socketpair$unix(0x1, 0x5, 0x0, &(0x7f0000000000)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})`,

		`r0 = socket$nl_generic(0x10, 0x3, 0x10)
r1 = syz_genetlink_get_family_id$ipvs(&(0x7f0000002000)='IPVS\x00', 0xffffffffffffffff)
sendmsg$IPVS_CMD_GET_CONFIG(r0, &(0x7f00000021c0)={0x0, 0x0, &(0x7f0000002180)={&(0x7f0000002040)={0x14, r1, 0x421}, 0x14}}, 0x0)`,
	}
	target, err := prog.GetTarget(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatalf("cannot get target: %v", err)
	}
	// rsMap, fdCallTb, nonFdCallTb := GenResourcesInfoTable(target, rsNames)
	for i, pStr := range progStrs {
		t.Logf("Test case %d", i)
		p, err := target.Deserialize([]byte(pStr), prog.NonStrict)
		if err != nil {
			t.Errorf("cannot parse program: %v", err)
		}
		l := ResourceCallAnalysis(p)
		for call, callMatchInfo := range l {
			t.Logf("call %v: %v", call, callMatchInfo.Name)
			for _, defUseInfo := range callMatchInfo.RsInfo {
				t.Logf("rs = %v, def = %v, use = %v, dup = %v",
					defUseInfo.RsName, defUseInfo.Def, defUseInfo.Use, defUseInfo.Dup)
			}
		}
	}
}
