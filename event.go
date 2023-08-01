package logon

import (
	"github.com/vela-ssoc/vela-process"
	"time"
)

const (
	SUCCESS = "登录成功"
	Fail    = "登录失败"
	Logout  = "用户注销"
)

type Event struct {
	RecordID uint64    `json:"record_id" storm:"id,unique,index"`
	MinionID string    `json:"minion_id"`
	Inet     string    `json:"inet"`
	Time     time.Time `json:"time"`
	Class    string    `json:"class"`
	Addr     string    `json:"addr" storm:"index"`
	Port     int       `json:"port"`
	User     string    `json:"user"`
	Host     string    `json:"host"`
	Pid      int32     `json:"pid"`
	Device   string    `json:"device"`
	Process  string    `json:"process"`
	Typ      string    `json:"type"` //linux type field
}

func (ev *Event) ref() {
	if ev.Process != "" {
		return
	}
	p, e := process.Pid(ev.Pid)
	if e != nil {
		return
	}
	ev.Process = p.Executable
}
