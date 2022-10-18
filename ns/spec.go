package ns

import (
	"fmt"
	"strings"

	"github.com/google/syzkaller/prog"
)

/*
	Note:
	- fd_fanotify/fd_inotify: mount?
	- fd_rdma: net?
	- fd_fscontext: mount?
	- fd_perf: ?
	- fd_devlink: reload operation allow device change net namespace, thus not allowed here
	- sock_nl_generic: ignore, there are specific netlink socket for certain device
	- genl_ieee802154_family_id/genl_nl802154_family_id: not namespaced
	- genl_nbd_family_id: network block device is namespaced?
	- hafnium: aarch type-1 hypervisor
	- isdn: legacy CAPI api
	- qrtr: interface communicating with services running on co-processors in Qualcomm platforms, guess not namespaced
	- sock creation source code checks the net must equal to init_net:
		- llc
		- netrom
		- nfc
		- rose
		- ax25
		- x25
		- hf (econet)
		- ipx
	- vsock does not support net ns
	- bt: reject net namespace supporting patch due to worring of information leakage:
		https://lore.kernel.org/lkml/20170814071640.289327-1-fupan.li@windriver.com/
	- rds_sock net ns support is incomplete (according to developer)

*/

type CallCheckFunc func(*prog.Call) bool
type NameFunc func(*prog.Call) string

type CallDesc struct {
	CallName string
	Checker  CallCheckFunc
	GetName  NameFunc
}

type SpecDescription struct {
	FdNames   []string
	FdDefCall []CallDesc
	NonFdCall []CallDesc
}

var defaultGetName = func(c *prog.Call) string {
	return c.Meta.Name
}
var defaultChecker = func(c *prog.Call) bool {
	return true
}

var ResourceSpec = map[NSType]SpecDescription{
	UserNS: {
		FdNames: []string{
			"uid",
			"gid",
		},
	},
	PidNS: {
		FdNames: []string{
			"pid",
		},
	},
	MntNS: {
		FdDefCall: []CallDesc{
			{
				CallName: `syz_open_procfs`,
				Checker: func(c *prog.Call) bool {
					dataRes := c.Args[1].(*prog.PointerArg).Res
					if dataRes == nil {
						return false
					}
					fn := string(dataRes.(*prog.DataArg).Data())
					mountFiles := []string{"mounts", "mountinfo", "mountstats"}
					match := false
					for _, f := range mountFiles {
						if strings.Contains(fn, f) {
							match = true
							break
						}
					}
					return match
				},
				GetName: func(c *prog.Call) string {
					name := c.Meta.Name
					dataRes := c.Args[1].(*prog.PointerArg).Res
					if dataRes == nil {
						return name
					}
					fn := string(dataRes.(*prog.DataArg).Data())
					return fmt.Sprintf(`%v(/proc/%v)`, name, fn)
				},
			},
		},
		NonFdCall: []CallDesc{
			{
				CallName: `mount`,
				Checker:  defaultChecker,
				GetName:  defaultGetName,
			},
			{
				CallName: `umount2`,
				Checker:  defaultChecker,
				GetName:  defaultGetName,
			},
			{
				CallName: `fsmount`,
				Checker:  defaultChecker,
				GetName:  defaultGetName,
			},
			{
				CallName: `move_mount`,
				Checker:  defaultChecker,
				GetName:  defaultGetName,
			},
			// below fs are allowed to mount in user namespace
			{
				CallName: `mount$tmpfs`,
				Checker:  defaultChecker,
				GetName:  defaultGetName,
			},
			{
				CallName: `mount$overlay`,
				Checker:  defaultChecker,
				GetName:  defaultGetName,
			},
			{
				CallName: `mount$bind`,
				Checker:  defaultChecker,
				GetName:  defaultGetName,
			},
			{
				CallName: `open`,
				Checker:  defaultChecker,
				GetName:  defaultGetName,
			},
			{
				CallName: `open$dir`,
				Checker:  defaultChecker,
				GetName:  defaultGetName,
			},
			{
				CallName: `openat$dir`,
				Checker:  defaultChecker,
				GetName:  defaultGetName,
			},
			{
				CallName: `openat`,
				Checker:  defaultChecker,
				GetName:  defaultGetName,
			},
			{
				CallName: `openat2$dir`,
				Checker:  defaultChecker,
				GetName:  defaultGetName,
			},
			{
				CallName: `openat2`,
				Checker:  defaultChecker,
				GetName:  defaultGetName,
			},
			{
				CallName: `creat`,
				Checker:  defaultChecker,
				GetName:  defaultGetName,
			},
		},
	},
	IPCNS: {
		FdNames: []string{
			"ipc_msq",
			"ipc_sem",
			"ipc_shm",
			"fd_mq",
		},
		FdDefCall: []CallDesc{
			{
				CallName: `openat$procfs`,
				Checker: func(c *prog.Call) bool {
					dataRes := c.Args[1].(*prog.PointerArg).Res
					if dataRes == nil {
						return false
					}
					fn := string(dataRes.(*prog.DataArg).Data())
					return strings.Contains(fn, `sysvipc/`)
				},
				GetName: func(c *prog.Call) string {
					name := c.Meta.Name
					dataRes := c.Args[1].(*prog.PointerArg).Res
					if dataRes == nil {
						return name
					}
					fn := string(dataRes.(*prog.DataArg).Data())
					return fmt.Sprintf(`%v(/proc/%v)`, name, fn)
				},
			},
		},
	},
	NetNS: {
		FdDefCall: []CallDesc{
			{
				CallName: `syz_open_procfs`,
				Checker: func(c *prog.Call) bool {
					dataRes := c.Args[1].(*prog.PointerArg).Res
					if dataRes == nil {
						return false
					}
					fn := string(dataRes.(*prog.DataArg).Data())
					return strings.Contains(fn, `net/`)
				},
				GetName: func(c *prog.Call) string {
					name := c.Meta.Name
					dataRes := c.Args[1].(*prog.PointerArg).Res
					if dataRes == nil {
						return name
					}
					fn := string(dataRes.(*prog.DataArg).Data())
					return fmt.Sprintf(`%v(/proc/%v)`, name, fn)
				},
			},
		},
		FdNames: []string{
			`sock_caif`,
			"batadv_hard_ifindex",
			"batadv_mesh_ifindex",
			"genl_batadv_family_id",
			"genl_ethtool_family_id",
			"genl_fou_family_id",
			"genl_ipvs_family_id",
			"genl_l2tp_family_id",
			"genl_mptcp_family_id",
			"genl_smc_family_id",
			"genl_team_family_id",
			"ifindex_team",
			"genl_tipc_family_id",
			"genl_tipc2_family_id",
			"genl_wireguard_family_id",
			"wireguard_ifindex",
			"sock_diag",
			"sock_dccp",
			"sock_dccp6",
			"sock_icmp",
			"sock_icmp6",
			"sock_in",
			"sock_in6",
			"sock_l2tp",
			"sock_l2tp6",
			"sock_netlink",
			"sock_nl_netfilter",
			"sock_nl_route",
			"sock_nl_crypto",
			"sock_nl_audit",
			"sock_nl_xfrm",
			"sock_phonet",
			"sock_phonet_dgram",
			"sock_phonet_pipe",
			"sock_pppl2tp",
			"sock_pppoe",
			"sock_pppox",
			// "sock_pptp",
			"sock_rxrpc",
			"sock_sctp",
			"sock_sctp6",
			"sock_tcp",
			"sock_tcp6",
			"sock_udp",
			"sock_udp6",
			"sock_tipc",
			"sock_xdp",
			"sock_unix",
			"sock_rds",
			"sock_can_raw",
			"sock_can_bcm",
		},
	},
}
