//go:build linux
// +build linux

package logon

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/vela-ssoc/vela-kit/audit"
	"github.com/vela-ssoc/vela-kit/auxlib"
	"github.com/vela-ssoc/vela-kit/lua"
	"gopkg.in/tomb.v2"
	"io"
	"os"
	"reflect"
	"sync/atomic"
	"time"
)

var (
	subscript uint32 = 0
	typeof    string = reflect.TypeOf((*Monitor)(nil)).String()
)

type Monitor struct {
	lua.SuperVelaData
	cfg  *config
	name string
	seek int64

	fd     *os.File
	reader *bufio.Reader
	tomb   *tomb.Tomb
}

func (m *Monitor) Name() string {
	return m.name
}

func (m *Monitor) Type() string {
	return typeof
}

func (m *Monitor) Start() error {
	go m.poll()
	return nil
}

func (m *Monitor) Close() error {
	m.tomb.Kill(nil)
	return nil
}

func (m *Monitor) save() {

	defer m.fd.Close() //关闭

	bkt := xEnv.Bucket(m.cfg.bkt...)
	seek, err := m.fd.Seek(0, io.SeekCurrent)
	if err != nil {
		xEnv.Errorf("%s wtmp got seek fail %v", m.name, err)
	}
	key := fmt.Sprintf("%s_seek", m.cfg.path)
	bkt.Store(key, seek, 0)
}

func (m *Monitor) InvalidUsername(s [][]byte) *Event {
	exe, pid := Convert2Pid(s[4])
	return &Event{
		User:    auxlib.B2S(s[10]),
		Addr:    auxlib.B2S(s[12]),
		Device:  "ps/0",
		Process: exe,
		Pid:     int32(pid),
		Class:   m.cfg.class,
		Time:    Convert2Time(s[0], s[1], s[2]),
	}
}
func (m *Monitor) InvalidPassword(s [][]byte) *Event {
	exe, pid := Convert2Pid(s[4])
	return &Event{
		User:    auxlib.B2S(s[8]),
		Addr:    auxlib.B2S(s[10]),
		Device:  "ps/0",
		Process: exe,
		Pid:     int32(pid),
		Class:   m.cfg.class,
		Time:    Convert2Time(s[0], s[1], s[2]),
	}

}

func (m *Monitor) bySecureFile(fd *os.File) (*Event, error) {
	var reader *bufio.Reader
	if m.reader == nil { //history
		reader = bufio.NewReaderSize(fd, 4096)
	} else {
		reader = m.reader
	}
	raw, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, err
	}

	if !bytes.Contains(raw, []byte("Failed password")) {
		return nil, nil
	}

	s := bytes.Split(raw, []byte(" "))

	switch len(s) {

	case 16:
		return m.InvalidUsername(s), nil

	case 14:
		return m.InvalidPassword(s), nil
	default:
		return nil, nil
	}

}

func (m *Monitor) track(fd *os.File) (*Event, error) {
	switch m.cfg.path {
	case "/var/log/wtmp":
		u, err := readUtmp(fd)
		if err != nil {
			return nil, err
		}

		if u.Type != 7 { //登录事件
			return nil, nil
		}

		return u.Event(m.cfg.class), nil

	case "/var/log/btmp":
		u, err := readUtmp(fd)
		if err != nil {
			return nil, err
		}
		return u.Event(m.cfg.class), nil

	case "/var/log/secure":
		return m.bySecureFile(fd)
	}
	return nil, fmt.Errorf("%s is not logon file", m.cfg.path)
}

func (m *Monitor) open() *os.File {
	for {
		select {
		case <-m.tomb.Dying():
			return nil

		default:
			fd, err := os.Open(m.cfg.path)
			if err != nil {
				audit.Errorf("%s %s open fail %v", m.Name(), m.cfg.path, err).Put()
				time.Sleep(time.Second * 30)
				continue
			}

			st, err := fd.Stat()
			if err != nil {
				audit.Errorf("%s %s read state fail %v", m.Name(), m.cfg.path, err).Put()
				time.Sleep(time.Second * 30)
				continue
			}

			m.fd = fd
			m.offset(st)

			if m.cfg.path == "/var/log/secure" {
				m.reader = bufio.NewReaderSize(fd, 4096)
			}

			return fd
		}
	}
}

func (m *Monitor) readline() {
	fd := m.open()
	if fd == nil {
		return
	}

	defer m.save()

	for {
		select {
		case <-m.tomb.Dying():
			return
		default:
			v, e := m.track(fd)
			if e == nil {
				m.cfg.handle(v)
				continue
			}

			if e.Error() == "EOF" {
				return
			}
			xEnv.Error("%s %v", m.cfg.path, e)
		}
	}
}

func (m *Monitor) cat() []*Event {
	fd, err := os.Open(m.cfg.path)
	if err != nil {
		audit.Errorf("%s utmp open fail %v", m.cfg.path, err).From(m.CodeVM()).Put()
		return nil
	}

	var ret []*Event
	collect := func(ev *Event) {
		if ev == nil {
			return
		}
		ret = append(ret, ev)
	}

	for {
		select {
		case <-m.tomb.Dying():
			return nil
		default:
			ev, e := m.track(fd)
			switch e {
			case io.EOF:
				return ret

			case nil:
				collect(ev)
			}
		}
	}

	return ret
}

func (m *Monitor) offset(s os.FileInfo) {
	bkt := xEnv.Bucket(m.cfg.bkt...)
	key := fmt.Sprintf("%s_seek", m.cfg.path)
	seek := bkt.Int64(key)
	if s.Size() < seek {
		return
	}
	m.fd.Seek(seek, 0)
}

func (m *Monitor) poll() {
	tk := time.NewTicker(time.Second)
	defer tk.Stop()

	for {
		select {
		case <-m.tomb.Dying():
			return
		case <-tk.C:
			m.readline()
		}
	}
}

func newMonitor(L *lua.LState, class, path string) *Monitor {
	name := fmt.Sprintf("linux.logon.%s.%d", class, atomic.AddUint32(&subscript, 1))
	cfg := newConfig(L, class, path)
	m := &Monitor{
		cfg:  cfg,
		tomb: new(tomb.Tomb),
		name: name,
	}
	m.V(lua.VTInit, typeof)
	return m
}
