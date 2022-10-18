package pgen

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"github.com/google/syzkaller/prog"
)

type FileProgGenerator struct {
	dir           string
	files         []os.FileInfo
	progTarget    *prog.Target
	progCache     []*prog.Prog
	progCacheName string
}

func InitFileProgGenerator(progTarget *prog.Target, dir string) (*FileProgGenerator, error) {
	var g *FileProgGenerator
	var err error

	g = &FileProgGenerator{
		dir:        dir,
		progTarget: progTarget,
	}
	g.files, err = ioutil.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("cannot list directory: %v", err)
	}
	return g, nil
}

func (g *FileProgGenerator) Generate() (*ProgGen, error) {
	var err error
	var data []byte
	var logs []*prog.LogEntry

	if len(g.progCache) != 0 {
		p := g.progCache[0]
		g.progCache = g.progCache[1:]
		return &ProgGen{P: p, Meta: &ProgMeta{Name: g.progCacheName}}, nil
	}
readFile:
	if len(g.files) == 0 {
		return nil, nil
	}
	name := g.files[0].Name()
	progPath := path.Join(g.dir, name)
	g.files = g.files[1:]
	data, err = ioutil.ReadFile(progPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open program file: %v", err)
	}
	logs = g.progTarget.ParseLog(data)
	if len(logs) == 0 {
		goto readFile
	}
	for i := 1; i < len(logs); i++ {
		g.progCache = append(g.progCache, logs[i].P)
	}
	if len(logs) > 1 {
		g.progCacheName = name
	}
	return &ProgGen{P: logs[0].P, Meta: &ProgMeta{Name: name}}, nil
}
