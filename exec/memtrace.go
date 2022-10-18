package exec

import "fmt"

type RawMemtracePkt struct {
	pc   [16]uint64
	addr [16]uint64
	info [16]uint32
}

const (
	MemtraceWrite uint32 = iota
	MemtraceRead
	MemtraceRet
	MemtraceCall
)

type MemTrace struct {
	Type uint32
	PC   uint64
	Addr uint64
	Len  uint32
}

func (pkt *RawMemtracePkt) ToMemTraces() []*MemTrace {
	t := make([]*MemTrace, 0, 16)
	for i := 0; i < 16; i++ {
		m := &MemTrace{
			Type: pkt.info[i] & 7,
			PC:   pkt.pc[i],
			Addr: pkt.addr[i],
			Len:  pkt.info[i] >> 3,
		}
		t = append(t, m)
	}
	return t
}

func (pkt *RawMemtracePkt) Deserialize(idx int) string {
	var rw byte
	if (pkt.info[idx] & 1) == 1 {
		rw = 'r'
	} else {
		rw = 'w'
	}
	len := pkt.info[idx] >> 1
	if len == 128 {
		// If you want to manually analyze pc (e.g. run addr2line) please disable KALSR!!
		return fmt.Sprintf("pc = %x, addr = %x, %c, len = %d",
			pkt.pc[idx], pkt.addr[idx], rw, len)
	} else {
		return fmt.Sprintf("pc = %x, addr = %x, %c, len = %d",
			pkt.pc[idx], pkt.addr[idx], rw, len)
	}
}

func DeserializeMemtrace(p []RawMemtracePkt, num int) string {
	s := ""
	for i := 0; i < num; i++ {
		s += p[0].Deserialize(i%16) + "\n"
		if (i % 16) == 15 {
			p = p[1:]
		}
	}
	return s
}
