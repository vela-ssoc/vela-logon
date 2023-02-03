//go:build windows
// +build windows

package logon

import (
	"fmt"
	"github.com/vela-ssoc/vela-kit/audit"
	"github.com/vela-ssoc/vela-evtlog/watch"
	"github.com/vela-ssoc/vela-kit/auxlib"
	"github.com/vela-ssoc/vela-kit/lua"
	"github.com/vela-ssoc/vela-kit/pipe"
	"gopkg.in/tomb.v2"
	"reflect"
	"sync/atomic"
)

var (
	subscript uint32 = 0
	typeof    string = reflect.TypeOf((*Monitor)(nil)).String()
)

type Monitor struct {
	lua.SuperVelaData
	cfg     *config
	bkt     []string
	begin   bool
	tomb    *tomb.Tomb
	watch   *watch.WinLogWatcher
	history *watch.WinLogWatcher
}

func Logon2Event(evt *watch.WinLogEvent) *Event {
	v, err := evt.EvData()
	if err != nil {
		xEnv.Errorf("%s convert to event data fail %v", err)
		return nil
	}

	return &Event{
		RecordID: evt.RecordId,
		MinionID: xEnv.ID(),
		Inet:     xEnv.Inet(),
		Time:     evt.Created,
		Addr:     v.Have("IpAddress"),
		User:     v.Have("TargetUserName"),
		Device:   v.Have("TargetDomainName"),
		Host:     evt.ComputerName,
		Pid:      int(evt.ProcessId),
		Process:  v.Have("ProcessName"),
	}
}

func (m *Monitor) historyHandle(ev *Event, pip *pipe.Px) {
	if ev == nil {
		return
	}

	if m.cfg.ref {
		ev.ref()
	}

	if m.cfg.ignore.Match(ev) {
		return
	}

	if !m.cfg.filter.Match(ev) {
		return
	}

	pip.Do(ev, m.cfg.co, func(err error) {
		xEnv.Errorf("%s history pipe call fail %v", m.Name(), err)
	})
}

func (m *Monitor) subscribe(name, query string) (err error) {
	if m.begin {
		m.watch.SubscribeFromBeginning(name, query)
		return
	}

	bookmark, err := xEnv.Bucket(m.bkt...).Value(name)
	if err != nil {
		err = m.watch.SubscribeFromBeginning(name, query)
		return
	}

	audit.NewEvent("vela-logon-record").
		Subject("%s last bookmark", name).
		From(m.cfg.co.CodeVM()).
		Msg("%s", bookmark).Log().Put()

	err = m.watch.SubscribeFromBookmark(name, query, auxlib.B2S(bookmark))
	return
}

func (m *Monitor) bookmark(evt *watch.WinLogEvent) {
	if len(m.bkt) == 0 {
		return
	}

	err := xEnv.Bucket(m.bkt...).Push(evt.Channel, auxlib.S2B(evt.Bookmark), 0)
	if err != nil {
		audit.NewEvent("vela-logon-evtlog").
			Subject("bbolt db save fail").
			From(m.cfg.co.CodeVM()).
			Msg("windows vela-event log save last fail").
			E(err).Log().Put()
	}
}

func (m *Monitor) toLogonEvent(evt *watch.WinLogEvent) *Event {
	v, err := evt.EvData()
	if err != nil {
		xEnv.Errorf("%s convert to event data fail %v", m.Name(), err)
		return nil
	}

	return &Event{
		MinionID: xEnv.ID(),
		Inet:     xEnv.Inet(),
		Class:    m.cfg.class,
		Time:     evt.Created,
		Addr:     v.IP(),
		User:     v.Have("TargetUserName"),
		Device:   v.Have("TargetDomainName"),
		Host:     evt.ComputerName,
		Pid:      int(evt.ProcessId),
		Process:  v.Have("ProcessName"),
	}
}

func (m *Monitor) accept() {
	defer m.watch.Shutdown()

	for {
		select {
		case <-m.tomb.Dying():
			return
		case evt := <-m.watch.Event():
			m.bookmark(evt)
			ev := m.toLogonEvent(evt)
			m.cfg.handle(ev)

		case err := <-m.watch.Error():
			audit.NewEvent("beat-windows-log").
				Subject("windows vela-event log fail").
				From(m.cfg.co.CodeVM()).
				Msg("windows 系统日志获取失败").
				E(err).Log().Put()
		}
	}
}

func (m *Monitor) Name() string {
	return m.cfg.name
}

func (m *Monitor) Type() string {
	return typeof
}

func (m *Monitor) Start() (err error) {
	w, e := watch.New()
	if e != nil {
		return e
	}

	m.watch = w

	err = m.subscribe("Security", m.cfg.path)
	if err != nil {
		return err
	}
	go m.accept()
	return nil
}

func (m *Monitor) Close() error {
	if m.tomb != nil {
		m.tomb.Killf("exit")
	}
	return nil
}

func newMonitor(L *lua.LState, class, query string) *Monitor {
	name := fmt.Sprintf("win.Logon.Monitor.%s.%d", class, atomic.AddUint32(&subscript, 1))
	cfg := newConfig(L, class, query) //not path windows
	cfg.name = name
	mtr := &Monitor{
		cfg: cfg,
		bkt: []string{"vela", "evtlog", "logon", class},
	}

	mtr.tomb = new(tomb.Tomb)
	mtr.V(lua.VTInit, typeof)
	return mtr
}
