package qemu

func (inst *instance) myhmp(cmd string) (err error) {
	req := &qmpCommand{
		Execute: "human-monitor-command",
		Arguments: &struct {
			Command string `json:"command-line"`
		}{
			Command: cmd,
		},
	}
	if err := inst.qmpConnCheck(); err != nil {
		return err
	}
	if err := inst.monEnc.Encode(req); err != nil {
		return err
	}
	for {
		res := make(map[string]interface{})
		err = inst.monDec.Decode(&res)
		if err != nil {
			return
		}
		if _, ok := res["timestamp"]; ok {
			continue
		}
		if _, ok := res["return"]; ok {
			break
		}
	}
	return
}

func (inst *instance) SaveSnapshot() error {
	return inst.myhmp("savevm img")
}

func (inst *instance) LoadSnapshot() error {
	return inst.myhmp("loadvm img")
}

func (inst *instance) Pause() error {
	return inst.myhmp("stop")
}

func (inst *instance) Resume() error {
	return inst.myhmp("cont")
}
