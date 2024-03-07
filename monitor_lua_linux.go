package logon

import (
	"github.com/vela-ssoc/vela-kit/lua"
	"github.com/vela-ssoc/vela-kit/pipe"
	"time"
)

func (m *Monitor) startL(L *lua.LState) int {
	xEnv.Errorf("%s start with %s", m.Name(), m.cfg.path)
	m.Start()
	m.V(lua.VTRun, time.Now())
	return 0
}

func (m *Monitor) historyL(L *lua.LState) int {
	pip := pipe.NewByLua(L)
	all := m.cat()
	if len(all) == 0 {
		return 0
	}

	for _, ev := range all {
		pip.Do(ev, m.cfg.co, func(err error) {
			xEnv.Errorf("%s history call fail %v", m.Name(), err)
		})
	}
	return 0
}

func (m *Monitor) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "start":
		return lua.NewFunction(m.startL)

	case "history":
		return lua.NewFunction(m.historyL)

	default:
		return m.cfg.Index(L, key)
	}
}
