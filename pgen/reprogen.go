package pgen

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"sync/atomic"
)

type ReproProg struct {
	CPMeta *CProgMeta `json:"cp_meta"`
}

type ReproTest struct {
	A *ReproProg `json:"a"`
	V *ReproProg `json:"v"`
}

type ReproConfig struct {
	Tests    []ReproTest `json:"tests"`
	SetupCmd string      `json:"setup_cmd"`
}

type ReproGenerator struct {
	config  *ReproConfig
	progDir string
	testIdx uint32
}

func InitReproTestGenerator(progDir, configPath string) (*ReproGenerator, error) {
	gen := &ReproGenerator{testIdx: 0, progDir: progDir}
	f, err := os.Open(configPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open repro config file: %v", err)
	}
	dec := json.NewDecoder(f)
	cfg := &ReproConfig{}
	err = dec.Decode(cfg)
	if err != nil {
		return nil, fmt.Errorf("cannot decode repro config file: %v", err)
	}
	gen.config = cfg
	return gen, nil
}

func (gen *ReproGenerator) Generate() (*ProgPair, error) {
	if int(gen.testIdx) == len(gen.config.Tests) {
		return nil, nil
	}
	test := gen.config.Tests[gen.testIdx]
	gen.testIdx++
	acp, err := ioutil.ReadFile(path.Join(gen.progDir, test.A.CPMeta.Name))
	if err != nil {
		return nil, fmt.Errorf("cannot read sender C program: %v", err)
	}
	vcp, err := ioutil.ReadFile(path.Join(gen.progDir, test.V.CPMeta.Name))
	if err != nil {
		return nil, fmt.Errorf("cannot read receiver C program: %v", err)
	}
	p := &ProgPair{
		A: &ProgGen{
			CP: &CProg{Code: acp, Meta: test.A.CPMeta},
		},
		V: &ProgGen{
			CP: &CProg{Code: vcp, Meta: test.V.CPMeta},
		},
	}
	// Ensure gob works well
	if p.A.CP.Meta.CompFlags == nil {
		p.A.CP.Meta.CompFlags = []string{}
	}
	if p.V.CP.Meta.CompFlags == nil {
		p.V.CP.Meta.CompFlags = []string{}
	}
	return p, nil
}

func (gen *ReproGenerator) Log() string {
	return fmt.Sprintf("repro, testIdx=%v", atomic.LoadUint32(&gen.testIdx))
}
