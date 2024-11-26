package logon

import (
	"encoding/json"
	"github.com/vela-ssoc/vela-kit/lua"
	risk "github.com/vela-ssoc/vela-risk"
	vtime "github.com/vela-ssoc/vela-time"
	"runtime"
	"strings"
)

func (ev *Event) String() string                         { return lua.B2S(ev.Byte()) }
func (ev *Event) Type() lua.LValueType                   { return lua.LTObject }
func (ev *Event) AssertFloat64() (float64, bool)         { return 0, false }
func (ev *Event) AssertString() (string, bool)           { return lua.B2S(ev.Byte()), true }
func (ev *Event) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (ev *Event) Peek() lua.LValue                       { return ev }

func (ev *Event) Byte() []byte {
	ev.OS = runtime.GOOS
	ev.Inet = xEnv.Inet()
	ev.MinionID = xEnv.ID()
	chunk, err := json.Marshal(ev)
	if err != nil {
		return nil
	}
	return chunk
}

func (ev *Event) reportL(L *lua.LState) int {
	err := xEnv.Push("/api/v1/broker/collect/agent/logon", ev)
	if err != nil {
		xEnv.Debugf("logon event report fail %v data:%v", err, ev)
	}
	return 0
}

func (ev *Event) riskL(L *lua.LState) int {
	ret := risk.NewEv(risk.Class(risk.TLogin))
	ret.RemoteIP = ev.Addr
	ret.RemotePort = ev.Port
	ret.LocalIP = ev.Inet
	ret.LocalPort = ev.Port
	ret.Payload = ev.User
	ret.FromCode = L.CodeVM()
	ret.Subject = ev.Class
	L.Push(ret)
	return 1
}

func (ev *Event) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "os":
		return lua.S2L(runtime.GOOS)
	case "minion_ip", "ip":
		return lua.S2L(xEnv.Inet())
	case "minion_id":
		return lua.S2L(xEnv.ID())
	case "user":
		return lua.S2L(ev.User)
	case "addr":
		return lua.S2L(ev.Addr)
	case "time":
		return vtime.VTime(ev.Time)
	case "host":
		return lua.S2L(ev.Host)
	case "pid":
		return lua.LInt(ev.Pid)
	case "class":
		return lua.S2L(ev.Class)
	case "process":
		return lua.S2L(ev.Process)
	case "type":
		return lua.S2L(ev.Typ)
	case "risk":
		return lua.NewFunction(ev.riskL)
	case "report":
		return lua.NewFunction(ev.reportL)
	default:
		if strings.HasPrefix(key, "exdata_") {
			value := ev.GetExdataAny(strings.TrimPrefix(key, "exdata_"))
			return lua.ToLValue(value)
		}
	}

	return lua.LNil
}
