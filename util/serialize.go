package util

import (
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/google/syzkaller/prog"
)

func ToGobFile(e interface{}, p string) error {
	f, err := os.Create(p)
	if err != nil {
		return fmt.Errorf("cannot create file: %v", err)
	}
	defer f.Close()
	enc := gob.NewEncoder(f)
	err = enc.Encode(e)
	if err != nil {
		return fmt.Errorf("cannot encode: %v", err)
	}
	return nil
}

func FromGobFile(d interface{}, p string) error {
	f, err := os.Open(p)
	if err != nil {
		return fmt.Errorf("cannot open file: %v", err)
	}
	defer f.Close()
	dec := gob.NewDecoder(f)
	err = dec.Decode(d)
	if err != nil {
		return fmt.Errorf("cannot decode: %v", err)
	}
	return nil
}

func ToJsonFile(e interface{}, p string) error {
	f, err := os.Create(p)
	if err != nil {
		return fmt.Errorf("cannot create file: %v", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent(" ", "\t")
	err = enc.Encode(e)
	if err != nil {
		return fmt.Errorf("cannot encode: %v", err)
	}
	return nil
}

func FromJsonFile(d interface{}, p string) error {
	f, err := os.Open(p)
	if err != nil {
		return fmt.Errorf("cannot open file: %v", err)
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	err = dec.Decode(d)
	if err != nil {
		return fmt.Errorf("cannot decode: %v", err)
	}
	return nil
}

func ReadProg(progPath string, target *prog.Target, mode prog.DeserializeMode) (*prog.Prog, error) {
	data, err := ioutil.ReadFile(progPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open program file: %v", err)
	}
	p, err := target.Deserialize(data, mode)
	if err != nil {
		return nil, fmt.Errorf("cannot deserialize program: %v", err)
	}
	return p, nil
}
