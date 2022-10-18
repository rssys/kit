package pgen

import "github.com/google/syzkaller/prog"

type ProgMeta struct {
	Name          string
	TestIdx       int
	ClsIdx        int
	ClsMemIdx     int
	ClsMemProgIdx int
	PredPC        uint64
	PredAddr      uint64
	PredAddrLen   uint8
}

type CProg struct {
	Code []byte
	Meta *CProgMeta
}

type CProgMeta struct {
	Name      string   `json:"name"`
	Compiler  string   `json:"compiler"`
	CompFlags []string `json:"comp_flags"`
}

type ProgGen struct {
	P    *prog.Prog
	Meta *ProgMeta
	CP   *CProg
}
type ProgPair struct {
	A *ProgGen
	V *ProgGen
	// currently deprecated
	Interleave bool
	VPause     uint8
}
type ProgGenerator interface {
	Generate() (*ProgGen, error)
}
type ProgPairGenerator interface {
	Generate() (*ProgPair, error)
	Log() string
}

func ProgramCheck(p *prog.Prog, s map[*prog.Syscall]bool) bool {
	for _, c := range p.Calls {
		if !s[c.Meta] {
			return false
		}
	}
	return true
}
