package logon

import (
	cond "github.com/vela-ssoc/vela-cond"
	"github.com/vela-ssoc/vela-kit/audit"
	"github.com/vela-ssoc/vela-kit/lua"
	"github.com/vela-ssoc/vela-kit/pipe"
	"github.com/vela-ssoc/vela-kit/windows/evtx"
	"time"
)

func (m *Monitor) startL(L *lua.LState) int {
	xEnv.Start(L, m).From(L.CodeVM()).Do()
	return 0
}

func (m *Monitor) historyL(L *lua.LState) int {
	pip := pipe.NewByLua(L)
	w, e := evtx.NewWatcher()
	if e != nil {
		audit.Errorf("windows %s history search fail %v", m.cfg.path, e).From(L.CodeVM()).Put()
		return 0
	}

	err := w.SubscribeFromBeginning("Security", m.cfg.path)
	if err != nil {
		audit.Errorf("windows %s history subscribe security fail %v", m.cfg.path, e).From(L.CodeVM()).Put()
		return 0
	}

	go func() {
		co := xEnv.Clone(L)
		tk := time.NewTicker(time.Second)
		defer func() {
			tk.Stop()
			w.Shutdown()
		}()

		backoff := 0
		for {
			select {
			case <-m.tomb.Dying():
				return
			case evt := <-w.Event():
				ev := m.toLogonEvent(evt)
				if m.cfg.ignore.Match(ev, cond.WithCo(co)) || !m.cfg.filter.Match(ev, cond.WithCo(co)) {
					continue
				}

				pip.Do(ev, co, func(err error) {
					xEnv.Errorf("%s windows security event parse fail %v", m.cfg.path, err)
				})

				backoff = 0

			case e := <-w.Error():
				audit.NewEvent("beat-windows-log").
					Subject("windows vela-event log fail").
					From(m.cfg.co.CodeVM()).
					Msg("windows 系统日志获取失败").
					E(e).Log().Put()

			case <-tk.C:
				backoff = backoff + 1
				if backoff > 30 {
					return
				}
			}
		}
	}()

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
